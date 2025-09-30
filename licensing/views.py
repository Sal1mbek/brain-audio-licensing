from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.utils import timezone
from django.conf import settings
from .models import LicenseKey, Activation
import jwt
from datetime import timedelta
from django.http import JsonResponse
import json

def make_jwt(lic: LicenseKey, device_id: str, days=30):
    if lic.expires_at is None:
        lic.expires_at = timezone.now() + timedelta(days=days)
        lic.save(update_fields=["expires_at"])

    exp = lic.expires_at
    payload = {
        "sub": f"license:{lic.id}",
        "lic": lic.id,
        "dev": device_id,
        "plan": lic.plan,
        "tv": lic.token_version,
        "iss": settings.JWT_ISSUER,
        "prod": "desktop-app",
        "exp": int(exp.timestamp()),
        "nbf": int(timezone.now().timestamp()),
    }
    token = jwt.encode(payload, settings.JWT_PRIVATE, algorithm=settings.JWT_ALG)
    return token, exp

def jwks_view(request):
    return JsonResponse({"keys": [settings.PUBLIC_JWK]})

class ActivateView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, req):
        key = (req.data.get("key") or "").upper().strip()
        device_id = (req.data.get("device_id") or "").strip()
        if not key or not device_id:
            return Response({"ok": False, "msg": "bad_request"}, status=400)
        try:
            lic = LicenseKey.objects.get(key=key)
        except LicenseKey.DoesNotExist:
            return Response({"ok": False, "msg": "invalid_key"}, status=400)

        if lic.status in ("EXPIRED", "REVOKED"):
            return Response({"ok": False, "msg": lic.status.lower()}, status=400)

        # привязка к устройству (1 устройство)
        active_count = Activation.objects.filter(license_key=lic, revoked=False).count()
        if not Activation.objects.filter(license_key=lic, device_id=device_id, revoked=False).exists():
            if active_count >= lic.max_devices:
                return Response({"ok": False, "msg": "too_many_devices"}, status=409)
            Activation.objects.create(license_key=lic, device_id=device_id)

        if lic.status == "ACTIVE":
            lic.status = "USED"

        # задать срок, если ещё не задан
        if lic.expires_at is None:
            lic.expires_at = timezone.now() + timedelta(days=30)

        lic.save(update_fields=["status", "expires_at"])

        token, exp = make_jwt(lic, device_id)
        return Response({
            "ok": True,
            "token": token,
            "expires_at": exp.isoformat(),
            "server_time": timezone.now().isoformat(),
            "plan": lic.plan
        })

class RefreshView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, req):
        token = req.data.get("token")
        device_id = (req.data.get("device_id") or "").strip()
        try:
            payload = jwt.decode(token, settings.JWT_PUBLIC, algorithms=[settings.JWT_ALG], options={"verify_aud": False})
        except Exception:
            return Response({"ok": False, "msg": "invalid_token"}, status=401)

        lic_id = payload.get("lic")
        tv = payload.get("tv")
        dev = payload.get("dev")

        if dev != device_id:
            return Response({"ok": False, "msg": "device_mismatch"}, status=409)

        lic = LicenseKey.objects.filter(id=lic_id).first()
        if not lic:
            return Response({"ok": False, "msg": "not_found"}, status=401)
        if lic.status in ("EXPIRED", "REVOKED"):
            return Response({"ok": False, "msg": "revoked_or_expired"}, status=401)
        if lic.expires_at and timezone.now() >= lic.expires_at:
            lic.status = "EXPIRED";
            lic.save(update_fields=["status"])
            return Response({"ok": False, "msg": "expired"}, status=401)
        if tv != lic.token_version:
            return Response({"ok": False, "msg": "token_version_mismatch"}, status=401)

        token, exp = make_jwt(lic, device_id)
        return Response({"ok": True, "token": token, "expires_at": exp.isoformat(), "server_time": timezone.now().isoformat()})

class IntrospectView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get("token")
        device_id = (request.data.get("device_id") or "").strip()
        if not token or not device_id:
            return Response({"ok": False, "err": "missing_params"}, status=400)

        try:
            payload = jwt.decode(
                token,
                settings.JWT_PUBLIC,
                algorithms=[settings.JWT_ALG],
                options={"verify_aud": False},   # aud не используем
                issuer=settings.JWT_ISSUER,
            )
        except Exception as e:
            # подпись/срок/issuer не прошли — токен невалиден
            return Response({"ok": False, "err": f"jwt_invalid: {e}"}, status=200)

        lic_id = payload.get("lic")
        tv = payload.get("tv")
        dev_in_token = payload.get("dev")

        # 1) device-id должен совпадать
        if dev_in_token != device_id:
            return Response({"ok": False, "err": "device_mismatch"}, status=200)

        # 2) лицензия должна существовать и быть активной
        lic = LicenseKey.objects.filter(id=lic_id).first()
        if not lic or lic.status in ("EXPIRED", "REVOKED"):
            return Response({"ok": False, "err": "revoked_or_expired"}, status=200)

        # 3) версия токена должна совпадать (анти-реюз/глобальный revoke)
        if tv != lic.token_version:
            return Response({"ok": False, "err": "token_version_mismatch"}, status=200)

        # 4) должна существовать активная привязка к ЭТОМУ устройству
        has_active = Activation.objects.filter(
            license_key=lic, device_id=device_id, revoked=False
        ).exists()
        if not has_active:
            return Response({"ok": False, "err": "no_active_activation_for_device"}, status=200)

        if lic.expires_at and timezone.now() >= lic.expires_at:
            lic.status = "EXPIRED";
            lic.save(update_fields=["status"])
            return Response({"ok": False, "err": "expired"}, status=200)

        # Все проверки пройдены
        return Response({"ok": True, "payload": payload})
