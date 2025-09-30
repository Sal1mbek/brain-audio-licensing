from django.contrib import admin
from .models import LicenseKey, Activation
from django.utils import timezone
from .utils import gen_key

@admin.register(LicenseKey)
class LicenseKeyAdmin(admin.ModelAdmin):
    list_display = ("key", "status", "plan", "expires_at", "token_version", "created_at")
    search_fields = ("key",)
    list_filter = ("status", "plan", "created_at")
    actions = ["generate_50_keys", "extend_30", "revoke", "bump_token_version"]

    def generate_50_keys(self, request, queryset):
        created = 0
        for _ in range(50):
            LicenseKey.objects.create(key=gen_key(), status="ACTIVE")
            created += 1
        self.message_user(request, f"Создано {created} ключей.")
    generate_50_keys.short_description = "Generate 50 keys"

    def extend_30(self, request, queryset):
        for lk in queryset:
            lk.token_version += 1
            lk.expires_at = (lk.expires_at or timezone.now()) + timezone.timedelta(days=30)
            lk.save()
    extend_30.short_description = "Extend +30 days (and bump token version)"

    def revoke(self, request, queryset):
        for lk in queryset:
            lk.status = "REVOKED"; lk.revoked_at = timezone.now(); lk.token_version += 1; lk.save()
    revoke.short_description = "Revoke"

    def bump_token_version(self, request, queryset):
        for lk in queryset:
            lk.token_version += 1; lk.save()
    bump_token_version.short_description = "Bump token version"

@admin.register(Activation)
class ActivationAdmin(admin.ModelAdmin):
    list_display = ("license_key", "device_id", "comment", "first_activated_at", "last_seen_at", "revoked")
    search_fields = ("device_id", "license_key__key")
