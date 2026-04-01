"""
Bootstrap the platform master tenant and its first admin user.
Safe to run multiple times (idempotent).

Required config.yml / env vars:
    PLATFORM_MASTER_REALM        - Keycloak realm for master tenant
    PLATFORM_MASTER_CLIENT_ID    - Keycloak client ID
    PLATFORM_MASTER_CLIENT_SECRET
    PLATFORM_KEYCLOAK_SERVER_URL - e.g. https://keycloak.example.com
    PLATFORM_ADMIN_USERNAME      - JumpServer admin username (maps to Keycloak subject)
    PLATFORM_ADMIN_EMAIL
"""
import logging
from django.core.management.base import BaseCommand
from django.db import transaction
from jumpserver.const import CONFIG

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Bootstrap master tenant and platform admin (idempotent)"

    def handle(self, *args, **options):
        self.stdout.write("Bootstrapping platform master tenant...")
        try:
            self._bootstrap()
            self.stdout.write(self.style.SUCCESS("Platform bootstrap complete."))
        except Exception as e:
            logger.error(f"Bootstrap failed: {e}", exc_info=True)
            raise

    @transaction.atomic
    def _bootstrap(self):
        from tenant_platform.models import Tenant, TenantKeycloakConfig, TenantAdminBinding
        from users.models import User

        # ── 1. Master Tenant ──────────────────────────────────────────────
        master_realm = CONFIG.get('PLATFORM_MASTER_REALM', 'master')
        tenant, created = Tenant.objects.get_or_create(
            is_master=True,
            defaults={
                'name': 'Master',
                'slug': master_realm,
                'is_active': True,
            }
        )
        if created:
            self.stdout.write(f"  Created master tenant: {tenant.name}")
        else:
            self.stdout.write(f"  Master tenant already exists: {tenant.name}")

        # ── 2. Keycloak Config for Master Tenant ──────────────────────────
        keycloak_url = CONFIG.get('PLATFORM_KEYCLOAK_SERVER_URL', '')
        client_id = CONFIG.get('PLATFORM_MASTER_CLIENT_ID', '')
        client_secret = CONFIG.get('PLATFORM_MASTER_CLIENT_SECRET', '')

        if not all([keycloak_url, client_id]):
            self.stdout.write(
                self.style.WARNING(
                    "  PLATFORM_KEYCLOAK_SERVER_URL or PLATFORM_MASTER_CLIENT_ID "
                    "not set — skipping Keycloak config. Set these in config.yml."
                )
            )
        else:
            kc_config, kc_created = TenantKeycloakConfig.objects.update_or_create(
                tenant=tenant,
                defaults={
                    'server_url': keycloak_url,
                    'realm': master_realm,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'scopes': 'openid email profile',
                    'pkce_enabled': True,
                    'pkce_method': 'S256',
                    'is_active': True,
                }
            )
            action = "Created" if kc_created else "Updated"
            self.stdout.write(f"  {action} Keycloak config for master tenant")

        # ── 3. Platform Admin User ────────────────────────────────────────
        admin_username = CONFIG.get('PLATFORM_ADMIN_USERNAME', 'platform-admin')
        admin_email = CONFIG.get('PLATFORM_ADMIN_EMAIL', 'admin@platform.local')

        user, user_created = User.objects.get_or_create(
            username=admin_username,
            defaults={
                'email': admin_email,
                'name': 'Platform Admin',
                'is_active': True,
                'is_superuser': True,  # JumpServer superuser
                # No password — auth is Keycloak-only
                'password': '!',  # Django convention: unusable password
            }
        )
        if user_created:
            user.set_unusable_password()
            user.save()
            self.stdout.write(f"  Created platform admin user: {admin_username}")
        else:
            self.stdout.write(f"  Platform admin already exists: {admin_username}")

        # ── 4. Bind Admin to Master Tenant ────────────────────────────────
        binding, _ = TenantAdminBinding.objects.get_or_create(
            tenant=tenant,
            user=user,
            defaults={'is_platform_admin': True}
        )
        self.stdout.write(f"  Admin bound to master tenant")