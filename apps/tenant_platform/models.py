import uuid
from django.db import models
from django.contrib.auth import get_user_model


class Tenant(models.Model):
    """
    One Tenant = one JumpServer Organization = one Keycloak Realm.
    The 'master' tenant is the platform-level admin tenant.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=128, unique=True)
    slug = models.SlugField(max_length=64, unique=True)  # used in URLs + realm matching
    is_master = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'tenant_platform'

    def __str__(self):
        return f"{self.name} ({'master' if self.is_master else 'tenant'})"

    @classmethod
    def get_master(cls):
        return cls.objects.filter(is_master=True).first()


class TenantKeycloakConfig(models.Model):
    """
    Per-tenant Keycloak OIDC configuration.
    One tenant has exactly one Keycloak config.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.OneToOneField(
        Tenant,
        on_delete=models.CASCADE,
        related_name='keycloak_config'
    )

    # Keycloak connection
    server_url = models.URLField(
        help_text="Base Keycloak URL e.g. https://keycloak.example.com"
    )
    realm = models.CharField(
        max_length=128,
        help_text="Keycloak realm name — must match tenant slug"
    )
    client_id = models.CharField(max_length=256)
    client_secret = models.CharField(
        max_length=512,
        blank=True,
        help_text="Leave blank for public clients (PKCE-only)"
    )

    # OIDC endpoints (auto-populated from discovery or set manually)
    discovery_url = models.URLField(
        blank=True,
        help_text="Auto-filled: {server_url}/realms/{realm}/.well-known/openid-configuration"
    )
    authorization_endpoint = models.URLField(blank=True)
    token_endpoint = models.URLField(blank=True)
    userinfo_endpoint = models.URLField(blank=True)
    jwks_uri = models.URLField(blank=True)
    end_session_endpoint = models.URLField(blank=True)

    # Behavior
    scopes = models.CharField(
        max_length=256,
        default="openid email profile",
        help_text="Space-separated OIDC scopes"
    )
    # Claim mappings: which Keycloak claim maps to JumpServer fields
    claim_username = models.CharField(max_length=64, default="preferred_username")
    claim_email = models.CharField(max_length=64, default="email")
    claim_name = models.CharField(max_length=64, default="name")
    claim_groups = models.CharField(
        max_length=64,
        default="groups",
        help_text="Keycloak claim that contains group memberships"
    )

    # PKCE
    pkce_enabled = models.BooleanField(default=True)
    pkce_method = models.CharField(
        max_length=8,
        default="S256",
        choices=[("S256", "SHA-256"), ("plain", "Plain")]
    )

    # Role mapping: Keycloak group name → JumpServer role name
    # JSON format: {"jumpserver-admins": "OrgAdmin", "jumpserver-auditors": "OrgAuditor"}
    role_mapping = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            'Map Keycloak groups to JumpServer roles. '
            'Format: {"keycloak-group": "JumpServerRole"} '
            'Valid roles: SystemAdmin, OrgAdmin, OrgAuditor, User'
        )
    )

    # Default role for users with no matching group
    default_role = models.CharField(
        max_length=64,
        default='User',
        help_text='Default JumpServer role for users with no matching Keycloak group'
    )

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'tenant_platform'

    def save(self, *args, **kwargs):
        # Auto-populate discovery URL if not set
        if not self.discovery_url and self.server_url and self.realm:
            self.discovery_url = (
                f"{self.server_url.rstrip('/')}/realms/{self.realm}"
                f"/.well-known/openid-configuration"
            )
        super().save(*args, **kwargs)

    @property
    def issuer(self):
        return f"{self.server_url.rstrip('/')}/realms/{self.realm}"


class TenantAdminBinding(models.Model):
    """
    Tracks which JumpServer users are admins of a tenant.
    Master tenant admins can manage all tenants.
    """
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name='admin_bindings'
    )
    user = models.ForeignKey(
        'users.User',
        on_delete=models.CASCADE,
        related_name='tenant_admin_bindings'
    )
    is_platform_admin = models.BooleanField(
        default=False,
        help_text="True only for master tenant admins who can manage all tenants"
    )

    class Meta:
        app_label = 'tenant_platform'
        unique_together = ('tenant', 'user')