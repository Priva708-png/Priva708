# server.py
import os
import time
import base64
from datetime import datetime, timedelta
from functools import wraps

from core.storage import ensure_admin_exists
ensure_admin_exists()

from flask import Flask, request, render_template, jsonify, redirect, url_for, make_response
import jwt

from core.storage import (
    load_users, save_users, load_bans, ensure_admin_exists, gen_msg_id,
    list_users_summary, ban_user, unban_user, disable_user, enable_user,
    reset_account, delete_user
)
from core.crypto import (
    make_password_hash, verify_password, generate_rsa_keypair,
    encrypt_with_password, hybrid_encrypt_for_public, hybrid_decrypt_with_private_enc,
    decrypt_with_password
)

# CONFIG
JWT_SECRET = os.environ.get('JWT_SECRET', 'change-this-secret-in-prod')
JWT_ALGO = 'HS256'
JWT_EXP_MINUTES = 60 * 24  # minutes (1 day)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Jinja filter for timestamps
@app.template_filter('datetimeformat')
def datetimeformat(value, fmt='%Y-%m-%d %H:%M'):
    try:
        return datetime.fromtimestamp(float(value)).strftime(fmt)
    except Exception:
        return "-"

# Ensure admin exists at startup
ensure_admin_exists()

def create_jwt(payload: dict, minutes=JWT_EXP_MINUTES):
    exp = datetime.utcnow() + timedelta(minutes=minutes)
    payload2 = payload.copy()
    payload2.update({'exp': exp})
    token = jwt.encode(payload2, JWT_SECRET, algorithm=JWT_ALGO)
    if isinstance(token, bytes):
        token = token.decode()
    return token

def decode_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except Exception:
        return None

def auth_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return redirect(url_for('login'))
        payload = decode_jwt(token)
        if not payload:
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('access_token', '', expires=0, httponly=True, samesite='Lax', secure=False)
            return resp
        request.user_email = payload.get('sub')
        return f(*args, **kwargs)
    return inner

def admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        payload = decode_jwt(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        email = payload.get('sub')
        users = load_users()
        u = users.get(email)
        if not u or not u.get('is_admin'):
            return jsonify({'error': 'Admin only'}), 403
        request.user_email = email
        return f(*args, **kwargs)
    return inner

# ---------- Pages ----------
@app.route('/')
def index():
    token = request.cookies.get('access_token')
    if token and decode_jwt(token):
        return redirect(url_for('inbox'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

# ---------- API: register/login/logout ----------
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json or request.form
    first = (data.get('first') or '').strip().capitalize()
    last = (data.get('last') or '').strip().upper()
    email = (data.get('email') or '').strip()
    code = data.get('code') or ''
    if not (first and last and email and code):
        return jsonify({'error': 'Champs manquants'}), 400
    bans = load_bans()
    if email in bans.get('emails', []):
        return jsonify({'error': 'Email banni'}), 403
    users = load_users()
    if email in users:
        return jsonify({'error': 'Compte existe déjà'}), 400
    priv_pem, pub_pem = generate_rsa_keypair()
    priv_encrypted_b64 = encrypt_with_password(priv_pem, code)
    pub_b64 = base64.b64encode(pub_pem).decode()
    pwdhash = make_password_hash(code)
    users[email] = {
        'first': first,
        'last': last,
        'password_hash': pwdhash,
        'pub_key': pub_b64,
        'priv_key_encrypted': priv_encrypted_b64,
        'inbox': [],
        'sentbox': [],
        'is_admin': False,
        'disabled': False,
        'created_at': time.time(),
        'meta': {}
    }
    save_users(users)
    return jsonify({'ok': True}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or request.form
    email = (data.get('email') or '').strip()
    code = data.get('code') or ''
    users = load_users()
    if email not in users:
        return jsonify({'error': 'Compte introuvable'}), 404
    u = users[email]
    if u.get('disabled'):
        return jsonify({'error': 'Compte désactivé'}), 403
    if not verify_password(code, u['password_hash']):
        return jsonify({'error': 'Code invalide'}), 401
    token = create_jwt({'sub': email, 'iat': int(time.time())})
    resp = make_response(jsonify({'ok': True}))
    # secure=True in prod (HTTPS)
    resp.set_cookie('access_token', token, httponly=True, samesite='Lax', secure=False, max_age=60*60*24)
    return resp

@app.route('/api/logout', methods=['POST'])
def api_logout():
    resp = make_response(jsonify({'ok': True}))
    resp.set_cookie('access_token', '', expires=0, httponly=True, samesite='Lax', secure=False)
    return resp

# ---------- Inbox page ----------
@app.route('/inbox', methods=['GET'])
@auth_required
def inbox():
    users = load_users()
    u = users.get(request.user_email)
    if not u:
        return redirect(url_for('login'))
    # Provide lightweight listings (id, from/to, timestamp, requires_code)
    inbox_entries = [{
        'id': m['id'],
        'from': m.get('from'),
        'requires_code': m.get('requires_code', False),
        'timestamp': m.get('timestamp', 0)
    } for m in sorted(u.get('inbox', []), key=lambda x: x.get('timestamp', 0), reverse=True)]
    sent_entries = [{
        'id': m['id'],
        'to': m.get('to'),
        'timestamp': m.get('timestamp', 0)
    } for m in sorted(u.get('sentbox', []), key=lambda x: x.get('timestamp', 0), reverse=True)]
    return render_template('inbox.html', user=u, inbox=inbox_entries, sent=sent_entries)

# ---------- API: send / read / delete ----------
@app.route('/api/message/send', methods=['POST'])
@auth_required
def api_message_send():
    data = request.json or request.form
    recipient = (data.get('recipient') or '').strip()
    content = data.get('content') or ''
    requires_code = bool(data.get('requires_code', False))
    code_for_recipient = data.get('code') if requires_code else None

    if not (recipient and content):
        return jsonify({'error': 'Destinataire et contenu requis'}), 400

    users = load_users()
    if recipient not in users:
        return jsonify({'error': 'Destinataire introuvable'}), 404

    # Encrypt payload for recipient
    pub_b64 = users[recipient].get('pub_key')
    if not pub_b64:
        return jsonify({'error': 'Destinataire sans clé publique'}), 400

    enc_struct = hybrid_encrypt_for_public(pub_b64, content)
    code_hash = None
    if requires_code and code_for_recipient:
        code_hash = make_password_hash(code_for_recipient)

    # Create message for recipient inbox
    msg = {
        'id': gen_msg_id(users),
        'from': request.user_email,
        'payload': enc_struct,
        'requires_code': requires_code,
        'code_hash': code_hash,
        'timestamp': time.time(),
        'sender_ip': request.remote_addr
    }
    users[recipient].setdefault('inbox', []).append(msg)

    # Create a sent copy for sender (store plaintext for convenience)
    sent_msg = {
        'id': msg['id'],
        'to': recipient,
        'plain': content,
        'requires_code': requires_code,
        'timestamp': msg['timestamp']
    }
    users.setdefault(request.user_email, {}).setdefault('sentbox', []).append(sent_msg)

    save_users(users)
    return jsonify({'ok': True, 'msg_id': msg['id']})

@app.route('/api/message/read', methods=['POST'])
@auth_required
def api_message_read():
    data = request.json or request.form
    box = data.get('box')  # 'inbox' or 'sent'
    try:
        msg_id = int(data.get('msg_id'))
    except Exception:
        return jsonify({'error': 'msg_id invalide'}), 400

    users = load_users()
    user = users.get(request.user_email)
    if not user:
        return jsonify({'error': 'Utilisateur introuvable'}), 404

    if box == 'inbox':
        # find message in inbox
        item = next((m for m in user.get('inbox', []) if m.get('id') == msg_id), None)
        if not item:
            return jsonify({'error': 'Message introuvable'}), 404
        # if protected by code, verify it
        if item.get('requires_code'):
            code = data.get('code') or ''
            if not code:
                return jsonify({'error': 'Code requis'}, 401)
            # verify code hash (hash stored for recipient)
            if not item.get('code_hash') or not verify_password(code, item.get('code_hash')):
                return jsonify({'error': 'Code invalide'}, 401)
        # decrypt recipient private key using user's provided code (their account code)
        # The private key was encrypted with the user's own account code at registration
        # The user must provide their account code here to unlock their private key
        account_code = data.get('account_code') or ''
        if not account_code:
            return jsonify({'error': 'account_code requis pour déchiffrement de la clé privée'}, 401)
        try:
            priv_encrypted_b64 = user.get('priv_key_encrypted')
            priv_pem = decrypt_with_password(priv_encrypted_b64, account_code)
        except Exception as e:
            return jsonify({'error': 'Impossible de déchiffrer la clé privée (account_code invalide?)'}), 401

        # Now decrypt the payload (hybrid)
        try:
            plaintext = hybrid_decrypt_with_private_enc(priv_pem, item['payload'])
        except Exception as e:
            return jsonify({'error': 'Déchiffrement message échoué'}), 500

        return jsonify({
            'ok': True,
            'from': item.get('from'),
            'timestamp': item.get('timestamp'),
            'plaintext': plaintext
        })

    elif box == 'sent':
        # sender looking at sentbox -> we stored plaintext in 'plain'
        item = next((m for m in user.get('sentbox', []) if m.get('id') == msg_id), None)
        if not item:
            return jsonify({'error': 'Message envoyé introuvable'}), 404
        return jsonify({
            'ok': True,
            'to': item.get('to'),
            'timestamp': item.get('timestamp'),
            'plaintext': item.get('plain')
        })
    else:
        return jsonify({'error': 'box invalide'}), 400

@app.route('/api/message/delete', methods=['POST'])
@auth_required
def api_message_delete():
    data = request.json or request.form
    box = data.get('box')
    try:
        msg_id = int(data.get('msg_id'))
    except Exception:
        return jsonify({'error': 'msg_id invalide'}), 400

    users = load_users()
    user = users.get(request.user_email)
    if not user:
        return jsonify({'error': 'Utilisateur introuvable'}), 404

    if box == 'inbox':
        before = len(user.get('inbox', []))
        user['inbox'] = [m for m in user.get('inbox', []) if m.get('id') != msg_id]
        save_users(users)
        return jsonify({'ok': True, 'removed': before - len(user['inbox'])})
    elif box == 'sent':
        before = len(user.get('sentbox', []))
        user['sentbox'] = [m for m in user.get('sentbox', []) if m.get('id') != msg_id]
        save_users(users)
        return jsonify({'ok': True, 'removed': before - len(user['sentbox'])})
    else:
        return jsonify({'error': 'box invalide'}), 400
    
@app.route('/api/users', methods=['GET'])
@auth_required
def api_users_list():
    users = load_users()
    emails = [e for e in users.keys()]
    return jsonify({'emails': emails})

# Admin page (UI)
@app.route('/admin', methods=['GET'])
@auth_required
def admin_page_redirect():
    # redirect only if user is admin, else back to inbox
    users = load_users()
    u = users.get(request.user_email)
    if not u or not u.get('is_admin'):
        return redirect(url_for('inbox'))
    return render_template('admin.html', user=u)

# API: list users summary (admin)
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_users():
    return jsonify({'users': list_users_summary()})

# API: ban / unban
@app.route('/api/admin/ban', methods=['POST'])
@admin_required
def api_admin_ban():
    data = request.json or request.form
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'email requis'}), 400
    ban_user(email)
    return jsonify({'ok': True})

@app.route('/api/admin/unban', methods=['POST'])
@admin_required
def api_admin_unban():
    data = request.json or request.form
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'email requis'}), 400
    unban_user(email)
    return jsonify({'ok': True})

# API: disable / enable account
@app.route('/api/admin/disable', methods=['POST'])
@admin_required
def api_admin_disable():
    data = request.json or request.form
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'email requis'}), 400
    ok = disable_user(email)
    if ok:
        return jsonify({'ok': True})
    return jsonify({'error': 'Utilisateur introuvable'}), 404

@app.route('/api/admin/enable', methods=['POST'])
@admin_required
def api_admin_enable():
    data = request.json or request.form
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'email requis'}), 400
    ok = enable_user(email)
    if ok:
        return jsonify({'ok': True})
    return jsonify({'error': 'Utilisateur introuvable'}), 404

# API: reset account (regenerate key + reset code). Admin can set new_code or let server generate one.
@app.route('/api/admin/reset_account', methods=['POST'])
@admin_required
def api_admin_reset_account():
    data = request.json or request.form
    email = (data.get('email') or '').strip()
    new_code = data.get('new_code') or None
    if not email:
        return jsonify({'error': 'email requis'}), 400
    ok, info = reset_account(email, new_code)
    if not ok:
        return jsonify({'error': info}), 404
    # info = new_code (string) returned
    return jsonify({'ok': True, 'new_code': info})

# API: delete user
@app.route('/api/admin/delete_user', methods=['POST'])
@admin_required
def api_admin_delete_user():
    data = request.json or request.form
    email = (data.get('email') or '').strip()
    if not email:
        return jsonify({'error': 'email requis'}), 400
    if email == request.user_email:
        return jsonify({'error': "Vous ne pouvez pas supprimer votre propre compte"}), 400
    ok = delete_user(email)
    if ok:
        return jsonify({'ok': True})
    return jsonify({'error': 'Utilisateur introuvable'}), 404

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)