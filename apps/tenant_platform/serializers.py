from rest_framework import serializers
from .models import Tenant, TenantKeycloakConfig


class TenantKeycloakConfigSerializer(serializers.ModelSerializer):
    # Write-only: never expose client_secret in GET responses
    client_secret = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = TenantKeycloakConfig
        exclude = ['id', 'tenant', 'created_at', 'updated_at']


class TenantSerializer(serializers.ModelSerializer):
    keycloak_config = TenantKeycloakConfigSerializer(required=False)

    class Meta:
        model = Tenant
        fields = [
            'id', 'name', 'slug', 'is_active', 'is_master',
            'created_at', 'updated_at', 'keycloak_config'
        ]
        read_only_fields = ['id', 'is_master', 'created_at', 'updated_at']

    def create(self, validated_data):
        kc_data = validated_data.pop('keycloak_config', None)
        tenant = Tenant.objects.create(**validated_data)
        if kc_data:
            TenantKeycloakConfig.objects.create(tenant=tenant, **kc_data)
        return tenant

    def update(self, instance, validated_data):
        kc_data = validated_data.pop('keycloak_config', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if kc_data:
            TenantKeycloakConfig.objects.update_or_create(
                tenant=instance, defaults=kc_data
            )
        return instance


class TenantKeycloakConfigUpdateSerializer(serializers.ModelSerializer):
    client_secret = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = TenantKeycloakConfig
        exclude = ['id', 'tenant', 'created_at', 'updated_at']