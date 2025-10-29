# server.py
import os
import time
import base64
from datetime import datetime, timedelta
from functools import wraps

from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet
eventlet.monkey_patch()

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
from flask import Flask, request, render_template, jsonify, redirect, url_for, make_response
import jwt

# ---------------- Config ----------------
JWT_SECRET = os.environ.get('JWT_SECRET', 'change-this-secret-in-prod')
JWT_ALGO = 'HS256'
JWT_EXP_MINUTES = 60 * 24

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# WebSocket
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Connected users
connected_users = {}

# ---------------- Jinja filter ----------------
@app.template_filter('datetimeformat')
def datetimeformat(value, fmt='%Y-%m-%d %H:%M'):
    try:
        return datetime.fromtimestamp(float(value)).strftime(fmt)
    except Exception:
        return "-"

# ---------------- Admin auto-setup ----------------
def ensure_super_admin():
    users = load_users()
    email = "admin@gmail.com"
    if email not in users:
        print("[setup] Création du compte Super Admin...")
        priv_pem, pub_pem = generate_rsa_keypair()
        code = "06122578685238242469440250169"
        priv_enc = encrypt_with_password(priv_pem, code)
        pub_b64 = base64.b64encode(pub_pem).decode()
        pwdhash = make_password_hash(code)
        users[email] = {
            'first': 'Super',
            'last': 'ADMIN',
            'password_hash': pwdhash,
            'pub_key': pub_b64,
            'priv_key_encrypted': priv_enc,
            'inbox': [],
            'sentbox': [],
            'is_admin': True,
            'disabled': False,
            'created_at': time.time(),
            'meta': {}
        }
        save_users(users)
        print(f"[setup] Super admin créé : {email}")
    else:
        if not users[email].get("is_admin"):
            users[email]["is_admin"] = True
            save_users(users)
            print("[setup] Super admin existant mis à jour.")

ensure_super_admin()

# ---------------- JWT utils ----------------
def create_jwt(payload: dict, minutes=JWT_EXP_MINUTES):
    exp = datetime.utcnow() + timedelta(minutes=minutes)
    payload2 = payload.copy()
    payload2.update({'exp': exp})
    token = jwt.encode(payload2, JWT_SECRET, algorithm=JWT_ALGO)
    return token.decode() if isinstance(token, bytes) else token

def decode_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None

# ---------------- Decorators ----------------
def auth_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return redirect(url_for('login'))
        payload = decode_jwt(token)
        if not payload:
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('access_token', '', expires=0)
            return resp
        request.user_email = payload.get('sub')
        return f(*args, **kwargs)
    return inner

def admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        token = request.cookies.get('access_token')
        payload = decode_jwt(token) if token else None
        if not payload:
            return jsonify({'error': 'Authentication required'}), 401
        email = payload.get('sub')
        users = load_users()
        u = users.get(email)
        if not u or not u.get('is_admin'):
            return jsonify({'error': 'Admin only'}), 403
        request.user_email = email
        return f(*args, **kwargs)
    return inner

# ---------------- Routes HTML ----------------
@app.route('/')
def index():
    token = request.cookies.get('access_token')
    if token and decode_jwt(token):
        return redirect(url_for('inbox'))
    return redirect(url_for('login'))

@app.route('/login')
def login(): return render_template('login.html')

@app.route('/register')
def register_page(): return render_template('register.html')

# ---------------- API: Auth ----------------
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
    u = users.get(email)
    if not u: return jsonify({'error': 'Compte introuvable'}), 404
    if u.get('disabled'): return jsonify({'error': 'Compte désactivé'}), 403
    if not verify_password(code, u['password_hash']):
        return jsonify({'error': 'Code invalide'}), 401
    token = create_jwt({'sub': email, 'iat': int(time.time())})
    resp = make_response(jsonify({'ok': True}))
    resp.set_cookie('access_token', token, httponly=True, max_age=86400)
    return resp

@app.route('/api/logout', methods=['POST'])
def api_logout():
    resp = make_response(jsonify({'ok': True}))
    resp.set_cookie('access_token', '', expires=0)
    return resp

# ---------------- Inbox ----------------
@app.route('/inbox')
@auth_required
def inbox():
    users = load_users()
    u = users.get(request.user_email)
    if not u:
        return redirect(url_for('login'))
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

# ---------------- API: Messaging ----------------
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

    pub_b64 = users[recipient].get('pub_key')
    enc_struct = hybrid_encrypt_for_public(pub_b64, content)
    code_hash = make_password_hash(code_for_recipient) if (requires_code and code_for_recipient) else None

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

    sent_msg = {
        'id': msg['id'],
        'to': recipient,
        'plain': content,
        'requires_code': requires_code,
        'timestamp': msg['timestamp']
    }
    users[request.user_email].setdefault('sentbox', []).append(sent_msg)
    save_users(users)
    return jsonify({'ok': True, 'msg_id': msg['id']})

# ---------------- WebRTC Socket.IO ----------------
@socketio.on('connect')
def on_connect(auth=None):
    token = request.cookies.get('access_token')
    payload = decode_jwt(token) if token else None
    if not payload:
        return False
    email = payload.get('sub')
    connected_users[email] = request.sid
    join_room(request.sid)
    print(f"[socket] connect: {email}")

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    for email, s in list(connected_users.items()):
        if s == sid:
            connected_users.pop(email, None)
            print(f"[socket] disconnect: {email}")

@socketio.on('webrtc_offer')
def on_webrtc_offer(data):
    to = data.get('to')
    if to in connected_users:
        emit('webrtc_offer', data, to=connected_users[to])

@socketio.on('webrtc_answer')
def on_webrtc_answer(data):
    to = data.get('to')
    if to in connected_users:
        emit('webrtc_answer', data, to=connected_users[to])

@socketio.on('webrtc_ice')
def on_webrtc_ice(data):
    to = data.get('to')
    if to in connected_users:
        emit('webrtc_ice', data, to=connected_users[to])

@socketio.on('call_user')
def on_call_user(data):
    to = data.get('to')
    if to in connected_users:
        emit('incoming_call', data, to=connected_users[to])

# ---------------- Admin Panel ----------------
@app.route('/admin')
@auth_required
def admin_page_redirect():
    users = load_users()
    u = users.get(request.user_email)
    if not u or not u.get('is_admin'):
        return redirect(url_for('inbox'))
    return render_template('admin.html', user=u)

@app.route('/api/users')
@auth_required
def api_users_list():
    users = load_users()
    return jsonify({'emails': list(users.keys())})

# ---------------- Run ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)
