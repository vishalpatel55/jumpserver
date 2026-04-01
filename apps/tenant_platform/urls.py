from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import TenantViewSet

app_name = 'tenant_platform'

router = DefaultRouter()
router.register('tenants', TenantViewSet, basename='tenant')

urlpatterns = router.urls