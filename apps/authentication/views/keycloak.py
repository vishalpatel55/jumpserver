"""
Keycloak OIDC + PKCE login views.

GET  /auth/keycloak/login/?tenant=<slug>
     → builds authorization URL with PKCE, redirects to Keycloak

GET  /auth/keycloak/callback/?code=...&state=...
     → validates state, exchanges code, validates token, creates session
"""
import logging
from urllib.parse import urlencode

from django.contrib.auth import login as auth_login
from django.http import HttpResponseRedirect, JsonResponse
from django.views import View
from django.conf import settings

from authentication.backends.keycloak import (
    generate_code_verifier,
    generate_code_challenge,
    generate_state,
    exchange_code_for_tokens,
    validate_id_token,
)

logger = logging.getLogger(__name__)


def get_redirect_uri(request):
    """Absolute callback URL — must include /core/ prefix for Nginx proxying."""
    return request.build_absolute_uri('/core/auth/keycloak/callback/')


class KeycloakLoginView(View):
    """
    Step 1: Initiate OIDC Authorization Code + PKCE flow.
    """

    def get(self, request):
        from tenant_platform.models import Tenant

        tenant_slug = request.GET.get('tenant')
        if not tenant_slug:
            tenant = getattr(request, 'tenant', None)
        else:
            try:
                tenant = Tenant.objects.select_related('keycloak_config').get(
                    slug=tenant_slug, is_active=True
                )
            except Tenant.DoesNotExist:
                return JsonResponse({'error': f'Tenant not found: {tenant_slug}'}, status=404)

        if not tenant:
            return JsonResponse({'error': 'No tenant context'}, status=400)

        try:
            kc_config = tenant.keycloak_config
        except Exception:
            return JsonResponse(
                {'error': f'Tenant {tenant_slug} has no Keycloak configuration'},
                status=503
            )

        if not kc_config.is_active:
            return JsonResponse({'error': 'Keycloak config is disabled'}, status=503)

        # ── PKCE ──────────────────────────────────────────────────────────
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier, kc_config.pkce_method)
        state = generate_state()

        # ── Sanitize next URL — never redirect back to root or login page ──
        next_url = request.GET.get('next', '/ui/')
        if not next_url or next_url in ('/', '/core/auth/login/', '/core/auth/login'):
            next_url = '/ui/'

        # Store verifier + state + tenant in session
        request.session['oidc_code_verifier'] = code_verifier
        request.session['oidc_state'] = state
        request.session['oidc_tenant_id'] = str(tenant.id)
        request.session['oidc_next'] = next_url
        request.session['last_tenant_slug'] = tenant.slug
        request.session.modified = True

        # ── Build Authorization URL ────────────────────────────────────────
        params = {
            'response_type': 'code',
            'client_id': kc_config.client_id,
            'redirect_uri': get_redirect_uri(request),
            'scope': kc_config.scopes,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': kc_config.pkce_method,
        }

        auth_url = f"{kc_config.authorization_endpoint}?{urlencode(params)}"
        logger.info(
            "Initiating Keycloak login for tenant=%s client_id=%s next=%s",
            tenant.slug, kc_config.client_id, next_url
        )
        return HttpResponseRedirect(auth_url)


class KeycloakCallbackView(View):
    """
    Step 2: Handle Keycloak callback, exchange code, create session.
    """

    def get(self, request):
        # ── Validate State ─────────────────────────────────────────────────
        returned_state = request.GET.get('state')
        stored_state = request.session.get('oidc_state')

        if not returned_state or returned_state != stored_state:
            logger.warning("OIDC state mismatch — possible CSRF")
            return JsonResponse({'error': 'Invalid state parameter'}, status=400)

        # ── Error from Keycloak ────────────────────────────────────────────
        error = request.GET.get('error')
        if error:
            error_desc = request.GET.get('error_description', '')
            logger.warning("Keycloak returned error: %s — %s", error, error_desc)
            return JsonResponse({'error': error, 'detail': error_desc}, status=401)

        code = request.GET.get('code')
        if not code:
            return JsonResponse({'error': 'Missing authorization code'}, status=400)

        # ── Retrieve PKCE state from session ──────────────────────────────
        code_verifier = request.session.get('oidc_code_verifier')
        tenant_id = request.session.get('oidc_tenant_id')
        next_url = request.session.pop('oidc_next', '/ui/')

        # Sanitize next_url again in case session had stale value
        if not next_url or next_url in ('/', '/core/auth/login/', '/core/auth/login'):
            next_url = '/ui/'

        if not code_verifier or not tenant_id:
            return JsonResponse({'error': 'Missing OIDC session state'}, status=400)

        # ── Load Tenant + Config ───────────────────────────────────────────
        from tenant_platform.models import Tenant
        try:
            tenant = Tenant.objects.select_related('keycloak_config').get(
                id=tenant_id, is_active=True
            )
            kc_config = tenant.keycloak_config
        except Exception as e:
            logger.error("Could not load tenant/config in callback: %s", e)
            return JsonResponse({'error': 'Tenant configuration error'}, status=500)

        # ── Exchange Code for Tokens ───────────────────────────────────────
        try:
            tokens = exchange_code_for_tokens(
                code=code,
                code_verifier=code_verifier,
                redirect_uri=get_redirect_uri(request),
                kc_config=kc_config,
            )
        except Exception as e:
            logger.error("Token exchange failed: %s", e)
            return JsonResponse({'error': 'Token exchange failed'}, status=401)

        # ── Validate ID Token ──────────────────────────────────────────────
        id_token = tokens.get('id_token')
        if not id_token:
            return JsonResponse({'error': 'No id_token in response'}, status=401)

        try:
            claims = validate_id_token(id_token, kc_config)
        except Exception as e:
            logger.error("Token validation failed: %s", e)
            return JsonResponse({'error': 'Token validation failed'}, status=401)

        # ── Authenticate / Get-or-Create User ─────────────────────────────
        from django.contrib.auth import authenticate
        user = authenticate(
            request,
            keycloak_claims=claims,
            tenant=tenant,
        )

        if user is None:
            return JsonResponse({'error': 'Authentication failed'}, status=401)

        if not user.is_active:
            return JsonResponse({'error': 'User account is disabled'}, status=403)

        # ── Create JumpServer Session ──────────────────────────────────────
        for key in ['oidc_code_verifier', 'oidc_state', 'oidc_tenant_id']:
            request.session.pop(key, None)

        request.session['tenant_id'] = str(tenant.id)
        request.session['oidc_id_token_hint'] = id_token
        request.session['oidc_access_token'] = tokens.get('access_token')

        auth_login(request, user,
                   backend='authentication.backends.keycloak.KeycloakOIDCBackend')

        logger.info(
            "Successful Keycloak login: user=%s tenant=%s next=%s",
            user.username, tenant.slug, next_url
        )
        return HttpResponseRedirect(next_url)


class KeycloakLogoutView(View):
    """
    Logout: invalidate JumpServer session + redirect to Keycloak end_session.
    """

    def get(self, request):
        from tenant_platform.models import Tenant

        id_token_hint = request.session.get('oidc_id_token_hint')
        tenant_id = request.session.get('tenant_id')

        request.session.flush()

        if tenant_id:
            try:
                tenant = Tenant.objects.select_related('keycloak_config').get(id=tenant_id)
                kc_config = tenant.keycloak_config
                if kc_config.end_session_endpoint:
                    params = {
                        'post_logout_redirect_uri': request.build_absolute_uri('/'),
                    }
                    if id_token_hint:
                        params['id_token_hint'] = id_token_hint
                    logout_url = f"{kc_config.end_session_endpoint}?{urlencode(params)}"
                    return HttpResponseRedirect(logout_url)
            except Exception as e:
                logger.warning("Could not build Keycloak logout URL: %s", e)

        return HttpResponseRedirect('/')