import secrets
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

def gen_key(groups=4, per=5):
    s = ''.join(secrets.choice(ALPHABET) for _ in range(groups*per))
    return '-'.join(s[i:i+per] for i in range(0, len(s), per))
