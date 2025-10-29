# core/storage.py
import os
import json
import time
import base64
from .crypto import generate_rsa_keypair, encrypt_with_password, make_password_hash

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
USERS_FILE = os.path.join(DATA_DIR, "users.json")
BANS_FILE = os.path.join(DATA_DIR, "bans.json")

# Super admin email and default code (CHANGE in production / use env)
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@gmail.com')
ADMIN_CODE = os.environ.get('ADMIN_CODE', 'change-admin-code-in-prod-please')

os.makedirs(DATA_DIR, exist_ok=True)

def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users: dict):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def load_bans() -> dict:
    if not os.path.exists(BANS_FILE):
        return {"emails": [], "ips": []}
    try:
        with open(BANS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {"emails": [], "ips": []}

def save_bans(bans: dict):
    with open(BANS_FILE, 'w', encoding='utf-8') as f:
        json.dump(bans, f, ensure_ascii=False, indent=2)

def gen_msg_id(users: dict) -> int:
    max_id = 0
    for u in users.values():
        for m in u.get('inbox', []):
            if 'id' in m and isinstance(m['id'], int):
                max_id = max(max_id, m['id'])
        for m in u.get('sentbox', []):
            if 'id' in m and isinstance(m['id'], int):
                max_id = max(max_id, m['id'])
    return max_id + 1

def ensure_admin_exists():
    """
    Vérifie si le super administrateur existe, sinon le crée automatiquement
    avec le code par défaut '06122578685238242469440250169'.
    """
    ADMIN_EMAIL = "admin@gmail.com"
    ADMIN_CODE = "06122578685238242469440250169"

    users = load_users()
    if ADMIN_EMAIL in users:
        # S'assurer que le flag admin est bien présent
        if not users[ADMIN_EMAIL].get('is_admin'):
            users[ADMIN_EMAIL]['is_admin'] = True
            save_users(users)
        return

    # Génération d'une nouvelle paire RSA pour l'admin
    priv_pem, pub_pem = generate_rsa_keypair()
    priv_encrypted_b64 = encrypt_with_password(priv_pem, ADMIN_CODE)
    pub_b64 = base64.b64encode(pub_pem).decode()
    pwdhash = make_password_hash(ADMIN_CODE)

    users[ADMIN_EMAIL] = {
        "first": "Super",
        "last": "Admin",
        "password_hash": pwdhash,
        "pub_key": pub_b64,
        "priv_key_encrypted": priv_encrypted_b64,
        "inbox": [],
        "sentbox": [],
        "is_admin": True,
        "disabled": False,
        "created_at": time.time(),
        "meta": {}
    }

    save_users(users)
    print(f"🛡️ Compte Super Admin créé : {ADMIN_EMAIL} / code : {ADMIN_CODE}")


# --------- Admin utilities ---------
def list_users_summary():
    users = load_users()
    out = []
    for email, u in users.items():
        out.append({
            'email': email,
            'first': u.get('first'),
            'last': u.get('last'),
            'is_admin': bool(u.get('is_admin', False)),
            'disabled': bool(u.get('disabled', False)),
            'inbox_count': len(u.get('inbox', [])),
            'sent_count': len(u.get('sentbox', [])),
            'created_at': u.get('created_at', 0)
        })
    return out

def ban_user(email: str):
    bans = load_bans()
    if 'emails' not in bans:
        bans['emails'] = []
    if email not in bans['emails']:
        bans['emails'].append(email)
    save_bans(bans)

def unban_user(email: str):
    bans = load_bans()
    if 'emails' in bans and email in bans['emails']:
        bans['emails'].remove(email)
    save_bans(bans)

def disable_user(email: str):
    users = load_users()
    if email in users:
        users[email]['disabled'] = True
        save_users(users)
        return True
    return False

def enable_user(email: str):
    users = load_users()
    if email in users:
        users[email]['disabled'] = False
        save_users(users)
        return True
    return False

def reset_account(email: str, new_code: str = None):
    """
    Reset a user's account: regenerate RSA keypair, re-encrypt private key with new_code,
    update stored password hash with new_code. Returns True on success.
    If new_code is None, generate a random code and return it.
    """
    users = load_users()
    if email not in users:
        return False, "Utilisateur introuvable"

    if new_code is None:
        # generate random code (hex)
        new_code = base64.b64encode(os.urandom(18)).decode()[:28]

    priv_pem, pub_pem = generate_rsa_keypair()
    priv_encrypted_b64 = encrypt_with_password(priv_pem, new_code)
    pub_b64 = base64.b64encode(pub_pem).decode()
    pwdhash = make_password_hash(new_code)

    users[email]['pub_key'] = pub_b64
    users[email]['priv_key_encrypted'] = priv_encrypted_b64
    users[email]['password_hash'] = pwdhash
    # optionally clear inbox/sent? keep existing messages (they won't be decryptable with old key)
    save_users(users)
    return True, new_code

def delete_user(email: str):
    users = load_users()
    if email in users:
        del users[email]
        save_users(users)
        return True
    return False
