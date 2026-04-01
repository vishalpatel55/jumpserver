from rest_framework.permissions import BasePermission


class IsPlatformAdmin(BasePermission):
    """
    Only users bound to the master tenant with is_platform_admin=True.
    """
    message = "Platform admin access required."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.tenant_admin_bindings.filter(
            tenant__is_master=True,
            is_platform_admin=True
        ).exists()