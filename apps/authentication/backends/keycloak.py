"""
Keycloak OIDC + OAuth2 Authorization Code + PKCE authentication backend.
"""
import base64
import hashlib
import logging
import os
from urllib.parse import urlencode

import requests
from django.contrib.auth import get_user_model
from django.core.cache import cache

from authentication.backends.base import JMSModelBackend

logger = logging.getLogger(__name__)
User = get_user_model()


# ── PKCE Helpers ──────────────────────────────────────────────────────────────

def generate_code_verifier(length=64) -> str:
    """RFC 7636 code_verifier: 43-128 chars, URL-safe chars only."""
    token = os.urandom(length)
    return base64.urlsafe_b64encode(token).rstrip(b'=').decode('ascii')


def generate_code_challenge(verifier: str, method: str = 'S256') -> str:
    """RFC 7636 code_challenge."""
    if method == 'S256':
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return verifier  # plain


def generate_state() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')


# ── Token Validation ──────────────────────────────────────────────────────────

def validate_id_token(id_token: str, kc_config) -> dict:
    """
    Validate the Keycloak id_token JWT.
    Verifies signature, iss, aud, exp.
    Returns decoded claims dict.
    """
    import jwt  # PyJWT

    jwks = jwt.PyJWKClient(kc_config.jwks_uri)
    signing_key = jwks.get_signing_key_from_jwt(id_token)

    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=kc_config.client_id,
        options={"verify_exp": True},
    )

    expected_iss = kc_config.issuer
    if claims.get('iss') != expected_iss:
        raise ValueError(
            f"Token issuer mismatch: expected {expected_iss}, got {claims.get('iss')}"
        )

    return claims


# ── Token Exchange ────────────────────────────────────────────────────────────

def exchange_code_for_tokens(code: str, code_verifier: str,
                              redirect_uri: str, kc_config) -> dict:
    """
    Exchange authorization code + PKCE verifier for tokens.
    Returns {'access_token', 'id_token', 'refresh_token', ...}
    """
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': kc_config.client_id,
        'code_verifier': code_verifier,
    }
    if kc_config.client_secret:
        data['client_secret'] = kc_config.client_secret

    resp = requests.post(
        kc_config.token_endpoint,
        data=data,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


# ── Django Auth Backend ───────────────────────────────────────────────────────

class KeycloakOIDCBackend(JMSModelBackend):
    """
    Django authentication backend for Keycloak OIDC.
    Called after token validation — receives validated claims + tenant.
    """

    def authenticate(self, request, keycloak_claims=None, tenant=None, **kwargs):
        if keycloak_claims is None or tenant is None:
            return None
        return self._get_or_create_user(keycloak_claims, tenant)

    def _get_or_create_user(self, claims: dict, tenant):
        kc_config = tenant.keycloak_config
        username = claims.get(kc_config.claim_username)
        email = claims.get(kc_config.claim_email, '')
        name = claims.get(kc_config.claim_name, username)

        if not username:
            logger.error(
                "Keycloak token missing username claim '%s'",
                kc_config.claim_username
            )
            return None

        namespaced_username = f"{tenant.slug}__{username}"

        # Step 1: try to find by namespaced username (fast path — already linked)
        user = User.objects.filter(username=namespaced_username).first()

        if user:
            # Sync mutable fields on every login
            changed = False
            if email and user.email != email:
                user.email = email
                changed = True
            if name and user.name != name:
                user.name = name
                changed = True
            if changed:
                user.save(update_fields=['email', 'name'])

        else:
            # Step 2: check if a user with this email already exists
            existing_by_email = (
                User.objects.filter(email=email).first() if email else None
            )

            if existing_by_email:
                # Link existing user to this tenant by updating their username
                logger.info(
                    "Linking existing user (email=%s, username=%s) "
                    "to tenant=%s with namespaced username=%s",
                    email, existing_by_email.username,
                    tenant.slug, namespaced_username
                )
                existing_by_email.username = namespaced_username
                existing_by_email.name = name or existing_by_email.name
                existing_by_email.is_active = True
                existing_by_email.source = 'keycloak'
                existing_by_email.save(
                    update_fields=['username', 'name', 'is_active', 'source']
                )
                user = existing_by_email

            else:
                # Step 3: create brand new user
                logger.info(
                    "Creating new user username=%s email=%s for tenant=%s",
                    namespaced_username, email, tenant.slug
                )
                user = User(
                    username=namespaced_username,
                    email=email,
                    name=name or username,
                    is_active=True,
                    source='keycloak',
                )
                user.set_unusable_password()
                user.save()

        # Bind user to tenant org
        self._bind_user_to_org(user, tenant)

        return user

    def _bind_user_to_org(self, user, tenant):
        """Add user to the JumpServer Organization that maps to this tenant."""
        from orgs.models import Organization

        org = self._get_or_create_org_for_tenant(tenant)
        org.add_member(user)
        

    def _get_or_create_org_for_tenant(self, tenant):
        from orgs.models import Organization

        org, created = Organization.objects.get_or_create(
            id=str(tenant.id),
            defaults={
                'name': tenant.name,
                'created_by': 'platform-bootstrap',
            }
        )
        if created:
            logger.info(
                "Created JumpServer org id=%s name=%s for tenant=%s",
                org.id, org.name, tenant.slug
            )
        return org

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None