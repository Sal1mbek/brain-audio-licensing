from django.db import models

ALPHABET = "ABCDEFGHJKMNOPQRSTUYWXYZ23456789"

class LicenseKey(models.Model):
    STATUS_CHOISES = [
        ("ACTIVE", "Active"),
        ("USED", "Used"),
        ("EXPIRED", "Expired"),
        ("REVOKED", "Revoked"),
    ]
    key = models.CharField(max_length=29, unique=True)
    plan = models.CharField(max_length=32, default="pro")
    status = models.CharField(max_length=16, choices=STATUS_CHOISES, default="ACTIVE")
    expires_at = models.DateTimeField(null=True, blank=True)
    max_devices = models.IntegerField(default=1)
    note = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    token_version = models.IntegerField(default=1)

    def __str__(self):
        return self.key

class Activation(models.Model):
    license_key = models.ForeignKey(LicenseKey, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=128)
    comment = models.TextField(blank=True, null=True)
    first_activated_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    revoked = models.BooleanField(default=False)

    class Meta:
        unique_together = ("license_key", "device_id")