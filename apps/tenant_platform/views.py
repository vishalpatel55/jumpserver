from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Tenant, TenantKeycloakConfig
from django.shortcuts import render

from .serializers import TenantSerializer, TenantKeycloakConfigUpdateSerializer
from .permissions import IsPlatformAdmin


class TenantViewSet(viewsets.ModelViewSet):
    """
    Platform admin API for tenant management.
    All endpoints require platform admin auth (master tenant Keycloak login).

    GET    /api/platform/tenants/              - list all tenants
    POST   /api/platform/tenants/              - create tenant
    GET    /api/platform/tenants/{id}/         - get tenant
    PATCH  /api/platform/tenants/{id}/         - update tenant
    DELETE /api/platform/tenants/{id}/         - deactivate tenant (soft delete)
    GET    /api/platform/tenants/{id}/keycloak/  - get Keycloak config
    PUT    /api/platform/tenants/{id}/keycloak/  - set/update Keycloak config
    POST   /api/platform/tenants/{id}/test_keycloak/ - test Keycloak connectivity
    """
    queryset = Tenant.objects.select_related('keycloak_config').all()
    serializer_class = TenantSerializer
    permission_classes = [IsPlatformAdmin]
    lookup_field = 'id'

    def destroy(self, request, *args, **kwargs):
        # Soft delete — never hard delete tenants
        tenant = self.get_object()
        if tenant.is_master:
            return Response(
                {'error': 'Cannot deactivate master tenant'},
                status=status.HTTP_400_BAD_REQUEST
            )
        tenant.is_active = False
        tenant.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['get', 'put', 'patch'], url_path='keycloak')
    def keycloak_config(self, request, id=None):
        tenant = self.get_object()

        if request.method == 'GET':
            try:
                config = tenant.keycloak_config
                serializer = TenantKeycloakConfigUpdateSerializer(config)
                return Response(serializer.data)
            except TenantKeycloakConfig.DoesNotExist:
                return Response(
                    {'error': 'No Keycloak config for this tenant'},
                    status=status.HTTP_404_NOT_FOUND
                )

        # PUT or PATCH
        partial = request.method == 'PATCH'
        try:
            config = tenant.keycloak_config
            serializer = TenantKeycloakConfigUpdateSerializer(
                config, data=request.data, partial=partial
            )
        except TenantKeycloakConfig.DoesNotExist:
            serializer = TenantKeycloakConfigUpdateSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        serializer.save(tenant=tenant)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='test_keycloak')
    def test_keycloak(self, request, id=None):
        """
        Test Keycloak connectivity by fetching the discovery document.
        """
        import requests as req
        tenant = self.get_object()
        try:
            kc_config = tenant.keycloak_config
        except TenantKeycloakConfig.DoesNotExist:
            return Response({'error': 'No Keycloak config'}, status=404)

        try:
            resp = req.get(kc_config.discovery_url, timeout=10)
            resp.raise_for_status()
            discovery = resp.json()

            # Auto-populate endpoints from discovery doc
            kc_config.authorization_endpoint = discovery.get('authorization_endpoint', '')
            kc_config.token_endpoint = discovery.get('token_endpoint', '')
            kc_config.userinfo_endpoint = discovery.get('userinfo_endpoint', '')
            kc_config.jwks_uri = discovery.get('jwks_uri', '')
            kc_config.end_session_endpoint = discovery.get('end_session_endpoint', '')
            kc_config.save()

            return Response({
                'status': 'ok',
                'issuer': discovery.get('issuer'),
                'endpoints_updated': True,
            })
        except Exception as e:
            return Response({'status': 'error', 'detail': str(e)}, status=502)
        
def tenant_login_selector(request):
    """Show all active tenants so user can pick which one to login to."""
    tenants = Tenant.objects.filter(is_active=True).select_related('keycloak_config')
    return render(request, 'tenant_platform/login_selector.html', {'tenants': tenants})