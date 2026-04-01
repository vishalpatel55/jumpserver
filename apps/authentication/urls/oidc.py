from django.urls import path
from authentication.views.keycloak import (
    KeycloakLoginView,
    KeycloakCallbackView,
    KeycloakLogoutView,
)

urlpatterns = [
    path('login/', KeycloakLoginView.as_view(), name='keycloak-login'),
    path('callback/', KeycloakCallbackView.as_view(), name='keycloak-callback'),
    path('logout/', KeycloakLogoutView.as_view(), name='keycloak-logout'),
]