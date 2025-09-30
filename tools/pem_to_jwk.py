# tools/pem_to_jwk.py
import base64, json, re
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

pub_pem = Path("keys/jwt_rs256_public.pem").read_bytes()
pub = serialization.load_pem_public_key(pub_pem)
nums: rsa.RSAPublicNumbers = pub.public_numbers()

def b64url(n: int) -> str:
    # int -> base64url без '='
    b = n.to_bytes((n.bit_length()+7)//8, "big")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

jwk = {
    "kty": "RSA",
    "n": b64url(nums.n),
    "e": b64url(nums.e),
    "alg": "RS256",
    "use": "sig",
    "kid": "v1"
}
print(json.dumps(jwk, indent=2))
