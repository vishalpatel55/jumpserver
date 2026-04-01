import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

# Exact path matches — checked before prefix matching
_EXEMPT_EXACT = (
    '/',
)

# Prefix matches
_EXEMPT_PATHS = (
    '/core/auth/',
    '/api/health/',
    '/health/',
    '/core/jsi18n/',
    '/static/',
    '/media/',
    '/api/swagger',
    '/api/docs',
    '/api/redoc',
    '/ui/',
    '/core/common/',
    '/core/flower/',
    '/core/redirect/',
    '/core/download/',
    '/core/i18n/',
)

# Paths used by satellite components (koko, lion, chen) — pass through without tenant
_COMPONENT_API_PATHS = (
    '/api/v1/users/profile/',
    '/api/v1/terminal/',
    '/api/v1/authentication/',
    '/api/v1/settings/',
    '/api/v1/assets/',
    '/api/v1/accounts/',
    '/api/v1/perms/',
    '/api/v1/orgs/',
    '/api/v1/rbac/',
    '/api/v1/acls/',
    '/api/v1/audits/',
    '/api/v1/notifications/',
    '/api/v1/labels/',
    '/api/v1/tickets/',
    '/api/v1/common/',
    '/api/v1/prometheus/',
    '/api/v1/search/',
    '/api/v1/index/',
    '/api/v1/reports/',
    '/api/v1/ops/',
)


class TenantMiddleware(MiddlewareMixin):

    def process_request(self, request):
        # Exact path exemptions
        if request.path in _EXEMPT_EXACT:
            request.tenant = None
            return None

        # Prefix path exemptions
        if any(request.path.startswith(p) for p in _EXEMPT_PATHS):
            request.tenant = None
            return None

        # Component API paths — koko/lion/chen authenticate via token, no tenant needed
        if any(request.path.startswith(p) for p in _COMPONENT_API_PATHS):
            request.tenant = None
            return None

        # Try to resolve tenant — catch all exceptions to avoid 500s
        try:
            tenant = (
                self._from_session(request)
                or self._from_header(request)
                or self._from_subdomain(request)
            )
        except Exception as e:
            logger.warning(f"TenantMiddleware error resolving tenant: {e}")
            request.tenant = None
            return None

        if tenant is None:
            # Platform API requires explicit tenant context
            if request.path.startswith('/api/v1/platform/'):
                return JsonResponse(
                    {'error': 'Tenant context required. Provide X-Tenant-Slug header.'},
                    status=400
                )
            # All other API calls from components — pass through without tenant
            if request.path.startswith('/api/'):
                request.tenant = None
                return None
            # Browser requests without tenant — redirect to tenant selector
            from django.shortcuts import redirect
            return redirect(f'/?next={request.path}')

        request.tenant = tenant
        self._activate_org(tenant)
        return None

    def _from_session(self, request):
        from tenant_platform.models import Tenant
        tenant_id = request.session.get('tenant_id')
        if not tenant_id:
            return None
        try:
            return Tenant.objects.select_related('keycloak_config').get(
                id=tenant_id, is_active=True
            )
        except Tenant.DoesNotExist:
            return None

    def _from_header(self, request):
        from tenant_platform.models import Tenant
        slug = request.headers.get('X-Tenant-Slug')
        if not slug:
            return None
        try:
            return Tenant.objects.select_related('keycloak_config').get(
                slug=slug, is_active=True
            )
        except Tenant.DoesNotExist:
            return None

    def _from_subdomain(self, request):
        from tenant_platform.models import Tenant
        host = request.get_host().split(':')[0]
        parts = host.split('.')
        if len(parts) < 3:
            return None
        slug = parts[0]
        try:
            return Tenant.objects.select_related('keycloak_config').get(
                slug=slug, is_active=True
            )
        except Tenant.DoesNotExist:
            return None

    def _activate_org(self, tenant):
        try:
            from orgs.utils import set_current_org
            from orgs.models import Organization
            org = Organization.objects.filter(id=str(tenant.id)).first()
            if org:
                set_current_org(org)
        except Exception as e:
            logger.warning(f"Could not activate org for tenant {tenant.slug}: {e}")