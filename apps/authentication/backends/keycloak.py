"""
Keycloak OIDC + OAuth2 Authorization Code + PKCE authentication backend.
"""
import base64
import hashlib
import logging
import os

import requests
from django.contrib.auth import get_user_model

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
            f"Token issuer mismatch: expected {expected_iss}, "
            f"got {claims.get('iss')}"
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

        # Step 1: try to find by namespaced username (fast path)
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
            # Step 2: check if email already exists
            existing_by_email = (
                User.objects.filter(email=email).first() if email else None
            )

            if existing_by_email:
                logger.info(
                    "Linking existing user email=%s username=%s "
                    "to tenant=%s as %s",
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
                    "Creating new user username=%s email=%s tenant=%s",
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

        # Bind user to this tenant's JumpServer org
        self._bind_user_to_org(user, tenant)

        # Assign JumpServer role based on Keycloak groups in token
        self._assign_roles(user, tenant, claims)

        # Master tenant users automatically become platform admins
        if tenant.is_master:
            self._ensure_platform_admin(user, tenant)

        return user

    # ── Org Binding ───────────────────────────────────────────────────────────

    def _bind_user_to_org(self, user, tenant):
        """Add user to the JumpServer Organization mapped to this tenant."""
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

    # ── Role Assignment ───────────────────────────────────────────────────────

    def _assign_roles(self, user, tenant, claims: dict):
        """
        Map Keycloak groups from the id_token to JumpServer RBAC roles.

        Flow:
          1. Read 'groups' claim from token  e.g. ["jumpserver-admins"]
          2. Look up role_mapping on TenantKeycloakConfig
             e.g. {"jumpserver-admins": "OrgAdmin", "jumpserver-users": "User"}
          3. First matching group wins → assign that JumpServer role in this org
          4. No match → assign default_role (default: "User")
          5. Remove stale org-scoped role bindings before assigning new one
             so re-login always reflects current Keycloak group membership
        """
        try:
            from rbac.models import Role, RoleBinding
            from orgs.models import Organization

            kc_config = tenant.keycloak_config
            role_mapping = kc_config.role_mapping or {}
            default_role_name = kc_config.default_role or 'User'

            # ── Read groups from token ─────────────────────────────────────
            # Keycloak sends groups as ["jumpserver-admins"] or ["/jumpserver-admins"]
            # depending on the "Full group path" mapper setting.
            raw_groups = claims.get(kc_config.claim_groups, [])
            # Normalise: strip leading slash so mapping keys don't need it
            user_groups = {g.lstrip('/') for g in raw_groups}

            logger.info(
                "Role assignment: user=%s groups=%s mapping=%s",
                user.username, user_groups, role_mapping
            )

            # ── Match group → role ─────────────────────────────────────────
            # First matching key in role_mapping wins.
            # Order matters if a user belongs to multiple groups —
            # put higher-privilege groups first in the mapping dict.
            target_role_name = default_role_name
            matched_group = None

            for kc_group, js_role in role_mapping.items():
                if kc_group in user_groups:
                    target_role_name = js_role
                    matched_group = kc_group
                    break

            if matched_group:
                logger.info(
                    "Matched group='%s' → role='%s' for user=%s",
                    matched_group, target_role_name, user.username
                )
            else:
                logger.info(
                    "No group match for user=%s — using default role='%s'",
                    user.username, target_role_name
                )

            # ── Resolve JumpServer role ────────────────────────────────────
            role = Role.objects.filter(name=target_role_name).first()
            if not role:
                logger.warning(
                    "Role '%s' not found in JumpServer, falling back to 'User'",
                    target_role_name
                )
                role = Role.objects.filter(name='User').first()

            if not role:
                logger.error(
                    "No roles found in JumpServer RBAC — skipping assignment "
                    "for user=%s", user.username
                )
                return

            # ── Get org for this tenant ────────────────────────────────────
            org = self._get_or_create_org_for_tenant(tenant)

            # ── Remove stale org-scoped bindings ───────────────────────────
            # Always refresh on login so role changes in Keycloak take effect
            # immediately on next login without manual intervention.
            deleted_count, _ = RoleBinding.objects.filter(
                user=user,
                org=org,
                role__scope='org',
            ).delete()
            if deleted_count:
                logger.info(
                    "Removed %d stale org role binding(s) for user=%s org=%s",
                    deleted_count, user.username, org.name
                )

            # ── Create new role binding ────────────────────────────────────
            RoleBinding.objects.get_or_create(
                user=user,
                role=role,
                org=org,
            )

            logger.info(
                "Assigned role='%s' to user=%s in org=%s",
                role.name, user.username, org.name
            )

        except Exception as e:
            # Never block login due to role assignment failure
            logger.error(
                "Role assignment failed for user=%s tenant=%s: %s",
                user.username, tenant.slug, e,
                exc_info=True
            )

    # ── Platform Admin ────────────────────────────────────────────────────────

    def _ensure_platform_admin(self, user, tenant):
        """
        Any user who successfully authenticates via the master tenant
        automatically gets a platform admin binding.
        This allows them to use the tenant management API.
        """
        try:
            from tenant_platform.models import TenantAdminBinding

            binding, created = TenantAdminBinding.objects.get_or_create(
                tenant=tenant,
                user=user,
                defaults={'is_platform_admin': True}
            )
            if not created and not binding.is_platform_admin:
                binding.is_platform_admin = True
                binding.save(update_fields=['is_platform_admin'])

            if created:
                logger.info(
                    "Created platform admin binding for user=%s",
                    user.username
                )
        except Exception as e:
            logger.error(
                "Platform admin binding failed for user=%s: %s",
                user.username, e,
                exc_info=True
            )

    # ── Django Backend Required Method ────────────────────────────────────────

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None