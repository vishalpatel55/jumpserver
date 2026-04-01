import logging
import requests
from django.core.management.base import BaseCommand
from tenant_platform.models import TenantKeycloakConfig

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync OIDC endpoints from Keycloak discovery documents"

    def handle(self, *args, **options):
        configs = TenantKeycloakConfig.objects.filter(is_active=True)
        for cfg in configs:
            self._sync(cfg)

    def _sync(self, cfg):
        try:
            resp = requests.get(cfg.discovery_url, timeout=10)
            resp.raise_for_status()
            doc = resp.json()
            cfg.authorization_endpoint = doc.get('authorization_endpoint', cfg.authorization_endpoint)
            cfg.token_endpoint = doc.get('token_endpoint', cfg.token_endpoint)
            cfg.userinfo_endpoint = doc.get('userinfo_endpoint', cfg.userinfo_endpoint)
            cfg.jwks_uri = doc.get('jwks_uri', cfg.jwks_uri)
            cfg.end_session_endpoint = doc.get('end_session_endpoint', cfg.end_session_endpoint)
            cfg.save()
            self.stdout.write(
                self.style.SUCCESS(f"  Synced endpoints for tenant: {cfg.tenant.slug}")
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"  Failed for tenant {cfg.tenant.slug}: {e}")
            )