#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Priva-708 — Messagerie privée et sécurisée
Version : interface modernisée (Tkinter pur, pas d'install supplémentaire)
Remarque : la logique crypto / stockage reste inchangée ; j'ai refait l'UI
pour un look plus ``flat / moderne`` en Tkinter pur (dark mode, sidebar,
cartes, boutons stylés). Aucune dépendance externe requise.
"""

import os
import json
import base64
import hmac
import time
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, filedialog
from tkinter import ttk

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from hashlib import scrypt
import socket
import shutil

# -----------------------------
# CONFIGURATION
# -----------------------------
DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
BANS_FILE = os.path.join(DATA_DIR, "bans.json")
os.makedirs(DATA_DIR, exist_ok=True)

DEBUG_SCRYPT = False
DEFAULT_SCRYPT = dict(n=2**14, r=8, p=1, dklen=32)
DEBUG_SCRYPT_PARAMS = dict(n=2**12, r=8, p=1, dklen=32)

# ADMIN credentials demandées
ADMIN_EMAIL = "ADMIN"
ADMIN_CODE = "06122578685238242469440250169"

def get_scrypt_params():
    return DEBUG_SCRYPT_PARAMS if DEBUG_SCRYPT else DEFAULT_SCRYPT

# -----------------------------
# UTILITAIRES CRYPTO
# -----------------------------
def make_password_hash(password: str) -> str:
    salt = os.urandom(16)
    params = get_scrypt_params()
    dk = scrypt(password.encode('utf-8'), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=params['dklen'])
    return base64.b64encode(salt + dk).decode()

def verify_password(password: str, b64saltdk: str) -> bool:
    try:
        raw = base64.b64decode(b64saltdk.encode())
        salt, dk = raw[:16], raw[16:]
        params = get_scrypt_params()
        newdk = scrypt(password.encode('utf-8'), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=len(dk))
        return hmac.compare_digest(newdk, dk)
    except Exception:
        return False

def encrypt_with_password(data: bytes, password: str) -> str:
    salt = os.urandom(16)
    params = get_scrypt_params()
    dk = scrypt(password.encode(), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=params['dklen'])
    f = Fernet(base64.urlsafe_b64encode(dk))
    token = f.encrypt(data)
    return base64.b64encode(salt + token).decode()

def decrypt_with_password(token_b64: str, password: str) -> bytes:
    raw = base64.b64decode(token_b64.encode())
    salt, token = raw[:16], raw[16:]
    params = get_scrypt_params()
    dk = scrypt(password.encode(), salt=salt, n=params['n'], r=params['r'], p=params['p'], dklen=params['dklen'])
    f = Fernet(base64.urlsafe_b64encode(dk))
    return f.decrypt(token)

def generate_rsa_keypair() -> (bytes, bytes):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem

def rsa_encrypt_with_public(pub_pem: bytes, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pub_pem)
    return pub.encrypt(plaintext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

def rsa_decrypt_with_private(priv_pem: bytes, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    return priv.decrypt(ciphertext, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

def hybrid_encrypt_for_public(pub_pem_b64: str, message: str) -> dict:
    pub_pem = base64.b64decode(pub_pem_b64.encode())
    fk = Fernet.generate_key()
    f = Fernet(fk)
    ciphertext = f.encrypt(message.encode()).decode()
    enc_fk = rsa_encrypt_with_public(pub_pem, fk)
    return {'enc_fkey': base64.b64encode(enc_fk).decode(), 'payload': ciphertext}

def hybrid_decrypt_with_private_enc(priv_pem_bytes: bytes, enc_struct: dict) -> str:
    enc_fk = base64.b64decode(enc_struct['enc_fkey'].encode())
    fk = rsa_decrypt_with_private(priv_pem_bytes, enc_fk)
    f = Fernet(fk)
    return f.decrypt(enc_struct['payload'].encode()).decode()

# -----------------------------
# Fichiers utilisateurs / bannissements / utilitaires
# -----------------------------
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
    return max_id + 1

# -----------------------------
# BOOT: création ADMIN si nécessaire
# -----------------------------
def ensure_admin_exists():
    users = load_users()
    if ADMIN_EMAIL in users:
        return
    priv_pem, pub_pem = generate_rsa_keypair()
    priv_encrypted_b64 = encrypt_with_password(priv_pem, ADMIN_CODE)
    pub_b64 = base64.b64encode(pub_pem).decode()
    pwdhash = make_password_hash(ADMIN_CODE)
    users[ADMIN_EMAIL] = {
        'first': 'Super',
        'last': 'Admin',
        'password_hash': pwdhash,
        'pub_key': pub_b64,
        'priv_key_encrypted': priv_encrypted_b64,
        'inbox': [],
        'is_admin': True,
        'disabled': False,
        'created_at': time.time(),
        'meta': {}
    }
    save_users(users)

# -----------------------------
# APPLICATION MODERNE (Tkinter pur)
# -----------------------------
class ModernStyle:
    """Couleurs et helpers pour donner un style moderne (dark / flat)."""
    BG = '#0f1720'
    PANEL = '#0b1220'
    CARD = '#0f1a2b'
    ACCENT = '#4f8ef7'
    MUTED = '#9aa7b2'
    TEXT = '#e6eef6'
    SUCCESS = '#2ecc71'

    @staticmethod
    def configure_tk(root):
        root.configure(bg=ModernStyle.BG)
        style = ttk.Style(root)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('TButton', font=('Segoe UI', 10), padding=8)
        style.configure('TLabel', font=('Segoe UI', 10), background=ModernStyle.BG, foreground=ModernStyle.TEXT)


class SecureMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Priva-708 — Messagerie privée et sécurisée")
        self.root.geometry("1100x700")
        ModernStyle.configure_tk(self.root)

        self.users = load_users()
        self.bans = load_bans()
        self.current_user = None
        self._session_private_key = None
        self.selected_recipient = None

        self._build_splash_then_home()

    # -----------------------------
    # UTIL
    # -----------------------------
    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def _show_busy(self, text='Opération en cours...'):
        # simple overlay
        self._busy = tk.Toplevel(self.root)
        self._busy.transient(self.root)
        self._busy.grab_set()
        self._busy.overrideredirect(True)
        s = tk.Frame(self._busy, bg=ModernStyle.PANEL, padx=20, pady=20)
        s.pack()
        tk.Label(s, text=text, fg=ModernStyle.TEXT, bg=ModernStyle.PANEL).pack()
        self._busy.update()

    def _hide_busy(self):
        try:
            if hasattr(self, '_busy') and self._busy:
                self._busy.grab_release()
                self._busy.destroy()
                self._busy = None
        except Exception:
            pass

    # -----------------------------
    # SPLASH THEN HOME
    # -----------------------------
    def _build_splash_then_home(self):
        self._clear()
        splash = tk.Frame(self.root, bg=ModernStyle.BG)
        splash.pack(fill=tk.BOTH, expand=True)
        tk.Label(splash, text='Priva-708', font=('Segoe UI', 40, 'bold'), fg=ModernStyle.ACCENT, bg=ModernStyle.BG).pack(pady=(80,10))
        tk.Label(splash, text='Messagerie privée et sécurisée', font=('Segoe UI', 14), fg=ModernStyle.MUTED, bg=ModernStyle.BG).pack()
        self.root.after(700, self._build_home)

    def _build_home(self):
        self._clear()
        # Top header
        header = tk.Frame(self.root, bg=ModernStyle.PANEL, height=64)
        header.pack(fill=tk.X)
        tk.Label(header, text='Priva-708', font=('Segoe UI', 18, 'bold'), fg=ModernStyle.ACCENT, bg=ModernStyle.PANEL).pack(side=tk.LEFT, padx=20)
        tk.Label(header, text='Messagerie privée et sécurisée — Interface modernisée (Tkinter)', font=('Segoe UI', 10), fg=ModernStyle.MUTED, bg=ModernStyle.PANEL).pack(side=tk.LEFT, padx=10)

        main = tk.Frame(self.root, bg=ModernStyle.BG)
        main.pack(fill=tk.BOTH, expand=True)

        # Left card
        left = tk.Frame(main, width=300, bg=ModernStyle.CARD, padx=12, pady=12)
        left.pack(side=tk.LEFT, fill=tk.Y)

        tk.Label(left, text='Bienvenue', font=('Segoe UI', 14, 'bold'), fg=ModernStyle.TEXT, bg=ModernStyle.CARD).pack(anchor='w')
        tk.Label(left, text='Connectez-vous ou créez un compte pour commencer.', fg=ModernStyle.MUTED, bg=ModernStyle.CARD).pack(anchor='w', pady=(0,8))

        btn_frame = tk.Frame(left, bg=ModernStyle.CARD)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text='Se connecter', command=self._show_login_dialog).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text='Créer un compte', command=self._show_register_dialog).pack(side=tk.LEFT, padx=6)

        ttk.Button(left, text='Options (réduire coût scrypt pour tests)', command=self._toggle_debug_scrypt).pack(fill=tk.X, pady=8)

        # Illustration / info
        info = tk.Label(left, text='Interface en Tkinter — design moderne, sans dépendances.', fg=ModernStyle.MUTED, bg=ModernStyle.CARD, wraplength=260, justify='left')
        info.pack(pady=12)

        # Center area - when not logged in show empty card
        center = tk.Frame(main, bg=ModernStyle.BG, padx=12, pady=12)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        card = tk.Frame(center, bg=ModernStyle.PANEL, padx=18, pady=18)
        card.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        tk.Label(card, text='Commencez', font=('Segoe UI', 16, 'bold'), fg=ModernStyle.TEXT, bg=ModernStyle.PANEL).pack(anchor='w')
        tk.Label(card, text='Connectez-vous pour voir votre boîte de réception et composer des messages.', fg=ModernStyle.MUTED, bg=ModernStyle.PANEL).pack(anchor='w', pady=(6,0))

    # -----------------------------
    # REGISTER / LOGIN (dialogues simplifiées)
    # -----------------------------
    def _show_register_dialog(self):
        first = simpledialog.askstring('Prénom', 'Entrez votre prénom :', parent=self.root)
        if first is None: return
        last = simpledialog.askstring('Nom de famille', 'Entrez votre nom de famille :', parent=self.root)
        if last is None: return
        email = simpledialog.askstring('Email', 'Entrez votre adresse e-mail :', parent=self.root)
        if email is None: return
        ip = simpledialog.askstring('IP (optionnel)', 'Entrez votre adresse IP / identifiant réseau (optionnel) :', initialvalue='127.0.0.1', parent=self.root)
        code = simpledialog.askstring('Code de sécurité', 'Choisissez un code :', show='*', parent=self.root)
        if code is None: return
        first = first.strip().capitalize(); last = last.strip().upper(); email = email.strip()
        if not (first and last and email and code):
            messagebox.showerror('Erreur', 'Tous les champs sont requis.', parent=self.root)
            return
        if email in self.bans.get('emails', []):
            messagebox.showerror('Interdit', 'Cet e-mail est banni.', parent=self.root)
            return
        if ip and any(ip.startswith(bip) for bip in self.bans.get('ips', [])):
            messagebox.showerror('Interdit', 'Cette IP est bannie.', parent=self.root)
            return
        if email in self.users:
            messagebox.showerror('Erreur', 'Un compte avec cet e-mail existe déjà.', parent=self.root)
            return
        priv_pem, pub_pem = generate_rsa_keypair()
        priv_encrypted_b64 = encrypt_with_password(priv_pem, code)
        pub_b64 = base64.b64encode(pub_pem).decode()
        pwdhash = make_password_hash(code)
        self.users[email] = {
            'first': first,
            'last': last,
            'password_hash': pwdhash,
            'pub_key': pub_b64,
            'priv_key_encrypted': priv_encrypted_b64,
            'inbox': [],
            'is_admin': False,
            'disabled': False,
            'created_at': time.time(),
            'meta': {'last_ip': ip or '127.0.0.1'}
        }
        save_users(self.users)
        messagebox.showinfo('Succès', 'Compte créé. La clé publique a été publiée; votre clé privée est protégée par votre code.', parent=self.root)

    def _show_login_dialog(self):
        email = simpledialog.askstring('Connexion', 'Adresse e-mail :', parent=self.root)
        if email is None: return
        code = simpledialog.askstring('Connexion', 'Code :', show='*', parent=self.root)
        if code is None: return
        threading.Thread(target=self._login_worker, args=(email.strip(), code), daemon=True).start()
        self._show_busy('Connexion...')

    def _login_worker(self, email, code):
        users = load_users()
        bans = load_bans()
        if email not in users:
            self.root.after(0, lambda: (self._hide_busy(), messagebox.showerror('Erreur', 'Compte introuvable.', parent=self.root))); return
        u = users[email]
        if u.get('disabled'):
            self.root.after(0, lambda: (self._hide_busy(), messagebox.showerror('Accès refusé', 'Ce compte est désactivé.', parent=self.root))); return
        if email in bans.get('emails', []):
            self.root.after(0, lambda: (self._hide_busy(), messagebox.showerror('Accès refusé', 'Cet e-mail est banni.', parent=self.root))); return
        if not verify_password(code, u['password_hash']):
            self.root.after(0, lambda: (self._hide_busy(), messagebox.showerror('Erreur', 'Code incorrect.', parent=self.root))); return
        try:
            priv_pem = decrypt_with_password(u['priv_key_encrypted'], code)
            self._session_private_key = priv_pem
        except Exception:
            self._session_private_key = None
        self.users = users
        self.bans = bans
        self.current_user = email
        self.root.after(0, lambda: (self._hide_busy(), self._build_main_ui(), self._post_login_prompt()))

    def _post_login_prompt(self):
        u = self.users.get(self.current_user, {})
        if u.get('is_admin'):
            ans = messagebox.askyesno('Mode Admin', 'Vous êtes connecté comme ADMIN. Voulez-vous ouvrir le panneau d\'administration ?', parent=self.root)
            if ans:
                self._open_admin_panel()
        else:
            if not self._session_private_key:
                ans = messagebox.askyesno('Déverrouiller clé', 'Souhaitez-vous déverrouiller votre clé privée maintenant pour envoyer et lire des messages sans retaper votre code ?', parent=self.root)
                if ans:
                    code = simpledialog.askstring('Code', 'Entrez votre code pour déverrouiller la clé :', show='*', parent=self.root)
                    if code:
                        try:
                            priv_pem = decrypt_with_password(self.users[self.current_user]['priv_key_encrypted'], code)
                            self._session_private_key = priv_pem
                            messagebox.showinfo('OK', 'Clé déverrouillée pour la session.', parent=self.root)
                        except Exception:
                            messagebox.showerror('Erreur', 'Code invalide — la clé n\'a pas été déverrouillée.', parent=self.root)

    def _toggle_debug_scrypt(self):
        global DEBUG_SCRYPT
        DEBUG_SCRYPT = not DEBUG_SCRYPT
        messagebox.showinfo('Option', f"DEBUG_SCRYPT = {DEBUG_SCRYPT}. Redémarrez l'application pour que le changement soit effectif pour les comptes existants.", parent=self.root)

    # -----------------------------
    # MAIN UI (modern) : sidebar, inbox, composer
    # -----------------------------
    def _build_main_ui(self):
        self._clear()
        # Header
        header = tk.Frame(self.root, bg=ModernStyle.PANEL, height=64)
        header.pack(fill=tk.X)
        u = self.users[self.current_user]
        tk.Label(header, text=f"Priva-708 — Connecté : {u['first']} {u['last']}", font=('Segoe UI', 12, 'bold'), fg=ModernStyle.TEXT, bg=ModernStyle.PANEL).pack(side=tk.LEFT, padx=16)
        tk.Button(header, text='Déconnexion', bg=ModernStyle.CARD, fg=ModernStyle.TEXT, relief='flat', command=self._logout).pack(side=tk.RIGHT, padx=12, pady=10)
        if u.get('is_admin'):
            tk.Button(header, text='Panneau Admin', bg=ModernStyle.ACCENT, fg='white', relief='flat', command=self._open_admin_panel).pack(side=tk.RIGHT, padx=12, pady=10)

        container = tk.Frame(self.root, bg=ModernStyle.BG)
        container.pack(fill=tk.BOTH, expand=True)

        # Sidebar (contacts)
        sidebar = tk.Frame(container, width=300, bg=ModernStyle.CARD, padx=10, pady=10)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(sidebar, text='Contacts', font=('Segoe UI', 12, 'bold'), fg=ModernStyle.TEXT, bg=ModernStyle.CARD).pack(anchor='w')
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(sidebar, textvariable=self.search_var, relief='flat')
        search_entry.pack(fill=tk.X, pady=(6,8))
        self.search_var.trace_add('write', lambda *a: self._refresh_contacts())

        self.contacts_listbox = tk.Listbox(sidebar, bg=ModernStyle.PANEL, fg=ModernStyle.TEXT, bd=0, highlightthickness=0)
        self.contacts_listbox.pack(fill=tk.BOTH, expand=True)
        ttk.Button(sidebar, text='Choisir destinataire', command=self._select_contact).pack(pady=6)
        ttk.Button(sidebar, text='Actualiser contacts', command=self._refresh_contacts).pack()

        # Center (inbox)
        center = tk.Frame(container, bg=ModernStyle.BG, padx=12, pady=12)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(center, text='Boîte de réception', font=('Segoe UI', 14, 'bold'), fg=ModernStyle.TEXT, bg=ModernStyle.BG).pack(anchor='w')
        self.inbox_listbox = tk.Listbox(center, bg=ModernStyle.PANEL, fg=ModernStyle.TEXT, bd=0, highlightthickness=0)
        self.inbox_listbox.pack(fill=tk.BOTH, expand=True, pady=(6,8))
        self.inbox_listbox.bind('<Double-1>', lambda e: self._open_message())
        btns = tk.Frame(center, bg=ModernStyle.BG)
        btns.pack()
        ttk.Button(btns, text='Ouvrir', command=self._open_message).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Supprimer', command=self._delete_message).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Actualiser boîte', command=self._refresh_inbox).pack(side=tk.LEFT, padx=6)

        # Right (compose)
        right = tk.Frame(container, width=360, bg=ModernStyle.CARD, padx=12, pady=12)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        tk.Label(right, text='Composer', font=('Segoe UI', 12, 'bold'), fg=ModernStyle.TEXT, bg=ModernStyle.CARD).pack(anchor='w')
        tk.Label(right, text='Destinataire:', fg=ModernStyle.MUTED, bg=ModernStyle.CARD).pack(anchor='w')
        self.selected_recipient_var = tk.StringVar(value='Aucun')
        tk.Label(right, textvariable=self.selected_recipient_var, fg=ModernStyle.ACCENT, bg=ModernStyle.CARD).pack(anchor='w')
        tk.Label(right, text='Message:', fg=ModernStyle.MUTED, bg=ModernStyle.CARD).pack(anchor='w', pady=(8,0))
        self.compose_txt = scrolledtext.ScrolledText(right, width=40, height=12)
        self.compose_txt.pack()
        self.protect_var = tk.BooleanVar(value=False)
        tk.Checkbutton(right, text='Protéger par code', var=self.protect_var, bg=ModernStyle.CARD, fg=ModernStyle.TEXT, selectcolor=ModernStyle.CARD).pack(anchor='w', pady=6)
        ttk.Button(right, text='Envoyer', command=self._attempt_send).pack(pady=6)

        self._refresh_contacts()
        self._refresh_inbox()

    def _refresh_all_from_disk(self):
        old_inbox_count = len(self.users.get(self.current_user, {}).get('inbox', [])) if self.current_user else 0
        self.users = load_users()
        self.bans = load_bans()
        new_inbox_count = len(self.users.get(self.current_user, {}).get('inbox', [])) if self.current_user else 0
        self._refresh_contacts()
        self._refresh_inbox()
        if new_inbox_count > old_inbox_count:
            messagebox.showinfo('Nouveaux messages', f'Vous avez {new_inbox_count - old_inbox_count} nouveau(x) message(s).', parent=self.root)

    def _refresh_contacts(self):
        q = self.search_var.get().lower() if hasattr(self, 'search_var') else ''
        self.contacts_listbox.delete(0, tk.END)
        for email, u in sorted(self.users.items(), key=lambda it: (it[1]['last'], it[1]['first'])):
            if email == self.current_user:
                continue
            label = f"{u['first']} {u['last']} <{email}>"
            if not q or q in label.lower() or q in email.lower():
                self.contacts_listbox.insert(tk.END, label)

    def _refresh_inbox(self):
        self.users = load_users()
        if not self.current_user:
            return
        inbox = self.users[self.current_user].get('inbox', [])
        self.inbox_listbox.delete(0, tk.END)
        for m in sorted(inbox, key=lambda x: x['timestamp'], reverse=True):
            sender = m['from']
            preview = '(protégé) ' if m.get('requires_code') else ''
            preview += f"de {self._display_name(sender)} — {time.strftime('%Y-%m-%d %H:%M', time.localtime(m['timestamp']))}"
            self.inbox_listbox.insert(tk.END, f"ID {m['id']} | {preview}")
        try:
            if len(inbox) > 5:
                self.compose_txt.configure(state=tk.DISABLED)
            else:
                self.compose_txt.configure(state=tk.NORMAL)
        except Exception:
            pass

    def _display_name(self, email):
        u = self.users.get(email)
        if not u:
            return email
        return f"{u['first']} {u['last']}"

    def _select_contact(self):
        sel = self.contacts_listbox.curselection()
        if not sel:
            messagebox.showwarning('Aucun destinataire', 'Sélectionnez un destinataire', parent=self.root)
            return
        text = self.contacts_listbox.get(sel[0])
        email = text.split('<')[-1].rstrip('>')
        self.selected_recipient = email
        self.selected_recipient_var.set(self._display_name(email) + f" — {email}")

    def _attempt_send(self):
        self.users = load_users()
        self.bans = load_bans()
        inbox = self.users[self.current_user].get('inbox', [])
        if len(inbox) > 5:
            messagebox.showerror('Limite', 'Votre boîte contient plus de 5 messages. Supprimez-en pour pouvoir envoyer.', parent=self.root)
            return
        if not self.selected_recipient:
            messagebox.showwarning('Destinataire', 'Sélectionnez un destinataire', parent=self.root)
            return
        recipient = self.selected_recipient
        if recipient not in self.users:
            messagebox.showerror('Erreur', 'Destinataire introuvable', parent=self.root)
            return
        if recipient in self.bans.get('emails', []):
            messagebox.showerror('Erreur', 'Le destinataire est banni.', parent=self.root)
            return
        content = self.compose_txt.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning('Vide', 'Le message est vide', parent=self.root)
            return
        requires_code = bool(self.protect_var.get())
        code_hash = None
        if requires_code:
            code = simpledialog.askstring('Code', 'Entrez le code que le destinataire devra fournir pour lire le message :', show='*', parent=self.root)
            if not code:
                messagebox.showwarning('Code requis', 'Aucun code fourni', parent=self.root)
                return
            code_hash = make_password_hash(code)
        pub_b64 = self.users[recipient].get('pub_key')
        if not pub_b64:
            messagebox.showerror('Erreur', 'Le destinataire n\'a pas de clé publique disponible.', parent=self.root)
            return
        enc_struct = hybrid_encrypt_for_public(pub_b64, content)
        try:
            sender_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            sender_ip = '127.0.0.1'
        msg = {'id': gen_msg_id(self.users), 'from': self.current_user, 'payload': enc_struct, 'requires_code': requires_code, 'code_hash': code_hash, 'timestamp': time.time(), 'sender_ip': sender_ip}
        users = load_users()
        users[recipient].setdefault('inbox', []).append(msg)
        save_users(users)
        messagebox.showinfo('Envoyé', 'Message envoyé et chiffré.', parent=self.root)
        self.compose_txt.delete('1.0', tk.END)
        self._refresh_inbox()

    def _open_message(self):
        sel = self.inbox_listbox.curselection()
        if not sel:
            messagebox.showwarning('Sélectionnez', 'Sélectionnez un message', parent=self.root)
            return
        line = self.inbox_listbox.get(sel[0])
        try:
            mid = int(line.split('|')[0].strip().split(' ')[1])
        except Exception:
            messagebox.showerror('Erreur', "Impossible d'identifier le message", parent=self.root); return
        inbox = self.users[self.current_user].get('inbox', [])
        msg = next((m for m in inbox if m['id'] == mid), None)
        if not msg:
            messagebox.showerror('Erreur', 'Message introuvable', parent=self.root); return
        if msg.get('requires_code'):
            code = simpledialog.askstring('Code requis', 'Entrez le code pour déchiffrer :', show='*', parent=self.root)
            if not code:
                return
            if not verify_password(code, msg.get('code_hash', '')):
                messagebox.showerror('Code incorrect', 'Le code est incorrect', parent=self.root); return
        priv_pem = self._session_private_key
        if not priv_pem:
            ans = messagebox.askyesno('Clé absente', 'Vous devez déverrouiller votre clé privée pour lire. Voulez-vous entrer votre code maintenant ?', parent=self.root)
            if not ans:
                return
            code = simpledialog.askstring('Code', 'Entrez votre code :', show='*', parent=self.root)
            if not code:
                return
            try:
                priv_pem = decrypt_with_password(self.users[self.current_user]['priv_key_encrypted'], code)
                self._session_private_key = priv_pem
            except Exception:
                messagebox.showerror('Erreur', 'Code invalide — impossible de déverrouiller la clé', parent=self.root); return
        try:
            plain = hybrid_decrypt_with_private_enc(priv_pem, msg['payload'])
        except Exception:
            messagebox.showerror('Erreur', 'Impossible de déchiffrer le message (clé ou payload incorrect).', parent=self.root); return
        win = tk.Toplevel(self.root)
        win.title(f"Message de {self._display_name(msg['from'])}")
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=80, height=20)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, plain)
        txt.configure(state=tk.DISABLED)
        def copycb():
            self.root.clipboard_clear()
            self.root.clipboard_append(plain)
            messagebox.showinfo('Copié', 'Message copié dans le presse-papier', parent=self.root)
        btnf = tk.Frame(win)
        btnf.pack(pady=6)
        ttk.Button(btnf, text='Copier', command=copycb).pack(side=tk.LEFT, padx=6)
        ttk.Button(btnf, text='Fermer', command=win.destroy).pack(side=tk.LEFT, padx=6)

    def _delete_message(self):
        sel = self.inbox_listbox.curselection()
        if not sel:
            messagebox.showwarning('Sélectionnez', 'Sélectionnez un message à supprimer', parent=self.root); return
        line = self.inbox_listbox.get(sel[0])
        try:
            mid = int(line.split('|')[0].strip().split(' ')[1])
        except Exception:
            messagebox.showerror('Erreur', "Impossible d'identifier le message", parent=self.root); return
        users = load_users()
        inbox = users[self.current_user].get('inbox', [])
        users[self.current_user]['inbox'] = [m for m in inbox if m['id'] != mid]
        save_users(users)
        messagebox.showinfo('Supprimé', 'Message supprimé', parent=self.root)
        self.users = users
        self._refresh_inbox()

    def _logout(self):
        self.current_user = None
        self._session_private_key = None
        self.selected_recipient = None
        self._build_home()

    # -----------------------------
    # Panneau Admin (modernisé)
    # -----------------------------
    def _open_admin_panel(self):
        if not self.current_user:
            messagebox.showerror('Accès', 'Non connecté', parent=self.root); return
        u = self.users.get(self.current_user, {})
        if not u.get('is_admin'):
            messagebox.showerror('Accès', 'Accès admin requis', parent=self.root); return

        admin_win = tk.Toplevel(self.root)
        admin_win.title('Panneau d\'administration — Priva-708')
        admin_win.geometry('950x620')
        admin_win.configure(bg=ModernStyle.BG)

        left = tk.Frame(admin_win, width=320, bg=ModernStyle.CARD, padx=10, pady=10)
        left.pack(side=tk.LEFT, fill=tk.Y)
        right = tk.Frame(admin_win, bg=ModernStyle.BG, padx=12, pady=12)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(left, text='Utilisateurs', font=('Segoe UI', 12, 'bold'), fg=ModernStyle.TEXT, bg=ModernStyle.CARD).pack(anchor='w')
        users_listbox = tk.Listbox(left, bg=ModernStyle.PANEL, fg=ModernStyle.TEXT)
        users_listbox.pack(fill=tk.BOTH, expand=True, pady=6)

        def refresh_users_list():
            users_listbox.delete(0, tk.END)
            self.users = load_users()
            for email, uu in sorted(self.users.items(), key=lambda it: (it[1].get('last'), it[1].get('first'))):
                tag = "[ADMIN] " if uu.get('is_admin') else ""
                tag += "[DISABLED] " if uu.get('disabled') else ""
                users_listbox.insert(tk.END, f"{tag}{uu.get('first')} {uu.get('last')} <{email}>")
        refresh_users_list()

        details_txt = scrolledtext.ScrolledText(right, height=15)
        details_txt.pack(fill=tk.X)

        action_frame = tk.Frame(right, bg=ModernStyle.BG)
        action_frame.pack(fill=tk.X, pady=6)

        def on_user_select(evt=None):
            sel = users_listbox.curselection()
            if not sel: return
            line = users_listbox.get(sel[0])
            email = line.split('<')[-1].rstrip('>')
            self.users = load_users()
            uu = self.users.get(email, {})
            details_txt.configure(state=tk.NORMAL)
            details_txt.delete('1.0', tk.END)
            details_txt.insert(tk.END, json.dumps({
                'email': email,
                'first': uu.get('first'),
                'last': uu.get('last'),
                'is_admin': uu.get('is_admin', False),
                'disabled': uu.get('disabled', False),
                'created_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(uu.get('created_at', 0))),
                'inbox_count': len(uu.get('inbox', [])),
                'meta': uu.get('meta', {})
            }, indent=2, ensure_ascii=False))
            details_txt.configure(state=tk.DISABLED)

        users_listbox.bind('<<ListboxSelect>>', on_user_select)

        def admin_disable_enable():
            sel = users_listbox.curselection()
            if not sel:
                messagebox.showwarning('Sélectionnez', 'Sélectionnez un utilisateur', parent=admin_win); return
            email = users_listbox.get(sel[0]).split('<')[-1].rstrip('>')
            if email == ADMIN_EMAIL:
                messagebox.showerror('Interdit', 'Impossible de désactiver ADMIN', parent=admin_win); return
            users = load_users()
            users[email]['disabled'] = not users[email].get('disabled', False)
            save_users(users)
            refresh_users_list()
            messagebox.showinfo('OK', f"Statut modifié pour {email}", parent=admin_win)

        def admin_force_reset():
            sel = users_listbox.curselection()
            if not sel:
                messagebox.showwarning('Sélectionnez', 'Sélectionnez un utilisateur', parent=admin_win); return
            email = users_listbox.get(sel[0]).split('<')[-1].rstrip('>')
            if email == ADMIN_EMAIL:
                messagebox.showerror('Interdit', 'Impossible de forcer reset sur ADMIN', parent=admin_win); return
            users = load_users()
            users[email].pop('priv_key_encrypted', None)
            users[email]['needs_reset'] = True
            save_users(users)
            refresh_users_list()
            messagebox.showinfo('OK', f"Réinitialisation forcée demandée pour {email}.", parent=admin_win)

        def admin_delete_user():
            sel = users_listbox.curselection()
            if not sel:
                messagebox.showwarning('Sélectionnez', 'Sélectionnez un utilisateur', parent=admin_win); return
            email = users_listbox.get(sel[0]).split('<')[-1].rstrip('>')
            if email == ADMIN_EMAIL:
                messagebox.showerror('Interdit', 'Impossible de supprimer ADMIN', parent=admin_win); return
            if messagebox.askyesno('Confirmer', f'Supprimer définitivement le compte {email} ?', parent=admin_win):
                users = load_users()
                users.pop(email, None)
                save_users(users)
                refresh_users_list()
                messagebox.showinfo('OK', f"{email} supprimé.", parent=admin_win)

        def admin_view_inbox_meta():
            sel = users_listbox.curselection()
            if not sel:
                messagebox.showwarning('Sélectionnez', 'Sélectionnez un utilisateur', parent=admin_win); return
            email = users_listbox.get(sel[0]).split('<')[-1].rstrip('>')
            users = load_users()
            inbox = users[email].get('inbox', [])
            meta_list = []
            for m in sorted(inbox, key=lambda x: x['timestamp'], reverse=True):
                meta_list.append({
                    'id': m['id'],
                    'from': m['from'],
                    'requires_code': m.get('requires_code', False),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(m.get('timestamp', 0))),
                    'sender_ip': m.get('sender_ip', 'unknown')
                })
            details_txt.configure(state=tk.NORMAL)
            details_txt.delete('1.0', tk.END)
            details_txt.insert(tk.END, json.dumps({'inbox_meta': meta_list}, indent=2, ensure_ascii=False))
            details_txt.configure(state=tk.DISABLED)

        def admin_delete_message_from_user():
            sel = users_listbox.curselection()
            if not sel:
                messagebox.showwarning('Sélectionnez', 'Sélectionnez un utilisateur', parent=admin_win); return
            email = users_listbox.get(sel[0]).split('<')[-1].rstrip('>')
            users = load_users()
            inbox = users[email].get('inbox', [])
            if not inbox:
                messagebox.showinfo('Info', 'Aucun message à supprimer pour cet utilisateur.', parent=admin_win); return
            ids = [str(m['id']) for m in inbox]
            chosen = simpledialog.askstring('Supprimer message', f"IDs disponibles pour {email}: {', '.join(ids)}\nEntrez l'ID à supprimer :", parent=admin_win)
            if not chosen:
                return
            try:
                cid = int(chosen)
            except Exception:
                messagebox.showerror('Erreur', 'ID invalide', parent=admin_win); return
            users[email]['inbox'] = [m for m in inbox if m['id'] != cid]
            save_users(users)
            messagebox.showinfo('OK', f"Message {cid} supprimé de la boîte de {email}.", parent=admin_win)
            on_user_select()

        def admin_ban_email():
            sel = users_listbox.curselection()
            if not sel:
                e = simpledialog.askstring('Bannir e-mail', 'Entrez l\'email à bannir :', parent=admin_win)
                if not e: return
                email_to_ban = e.strip()
            else:
                email_to_ban = users_listbox.get(sel[0]).split('<')[-1].rstrip('>')
            if email_to_ban == ADMIN_EMAIL:
                messagebox.showerror('Interdit', 'Impossible de bannir ADMIN', parent=admin_win); return
            bans = load_bans()
            if email_to_ban not in bans['emails']:
                bans['emails'].append(email_to_ban)
                save_bans(bans)
                messagebox.showinfo('OK', f"{email_to_ban} a été banni (email).", parent=admin_win)
            else:
                messagebox.showinfo('Info', 'Déjà banni.', parent=admin_win)

        def admin_unban_email():
            bans = load_bans()
            if not bans['emails']:
                messagebox.showinfo('Info', 'Aucun email banni.', parent=admin_win); return
            chosen = simpledialog.askstring('Débannir email', f"Emails bannis:\n{', '.join(bans['emails'])}\nEntrez l'email à débannir :", parent=admin_win)
            if not chosen: return
            if chosen in bans['emails']:
                bans['emails'].remove(chosen)
                save_bans(bans)
                messagebox.showinfo('OK', f"{chosen} débanni.", parent=admin_win)
            else:
                messagebox.showinfo('Info', 'Cet email n\'est pas dans la liste.', parent=admin_win)

        def admin_ban_ip():
            ip = simpledialog.askstring('Bannir IP', 'Entrez le préfixe / IP à bannir (ex: 192.168 ou 10.0.0.5) :', parent=admin_win)
            if not ip: return
            bans = load_bans()
            if ip not in bans['ips']:
                bans['ips'].append(ip)
                save_bans(bans)
                messagebox.showinfo('OK', f"{ip} a été banni (IP).", parent=admin_win)
            else:
                messagebox.showinfo('Info', 'Déjà banni.', parent=admin_win)

        def admin_unban_ip():
            bans = load_bans()
            if not bans['ips']:
                messagebox.showinfo('Info', 'Aucune IP bannie.', parent=admin_win); return
            chosen = simpledialog.askstring('Débannir IP', f"IPs bannies:\n{', '.join(bans['ips'])}\nEntrez l'IP à débannir :", parent=admin_win)
            if not chosen: return
            if chosen in bans['ips']:
                bans['ips'].remove(chosen)
                save_bans(bans)
                messagebox.showinfo('OK', f"{chosen} débanni.", parent=admin_win)
            else:
                messagebox.showinfo('Info', 'Cette IP n\'est pas dans la liste.', parent=admin_win)

        def admin_backup():
            src = USERS_FILE
            if not os.path.exists(src):
                messagebox.showerror('Erreur', 'Aucune base à sauvegarder.', parent=admin_win); return
            dst = filedialog.asksaveasfilename(title='Sauvegarder users.json', defaultextension='.json', filetypes=[('JSON files', '*.json')], parent=admin_win)
            if not dst: return
            try:
                shutil.copy2(src, dst)
                messagebox.showinfo('OK', f'Sauvegarde réalisée: {dst}', parent=admin_win)
            except Exception as e:
                messagebox.showerror('Erreur', f'Impossible de sauvegarder: {e}', parent=admin_win)

        def admin_restore():
            if not messagebox.askyesno('Restaurer', 'Restaurer remplacera la base actuelle. Continuer ?', parent=admin_win):
                return
            src = filedialog.askopenfilename(title='Restaurer users.json', filetypes=[('JSON files', '*.json')], parent=admin_win)
            if not src: return
            try:
                shutil.copy2(src, USERS_FILE)
                self.users = load_users()
                refresh_users_list()
                messagebox.showinfo('OK', 'Restauration terminée.', parent=admin_win)
            except Exception as e:
                messagebox.showerror('Erreur', f'Impossible de restaurer: {e}', parent=admin_win)

        # Layout boutons
        tk.Button(action_frame, text='Désactiver/Activer', command=admin_disable_enable, bg=ModernStyle.PANEL, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)
        tk.Button(action_frame, text='Forcer reset', command=admin_force_reset, bg=ModernStyle.CARD, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)
        tk.Button(action_frame, text='Supprimer compte', command=admin_delete_user, bg=ModernStyle.ACCENT, fg='white').pack(side=tk.LEFT, padx=6)

        action_frame2 = tk.Frame(right, bg=ModernStyle.BG)
        action_frame2.pack(fill=tk.X, pady=6)
        tk.Button(action_frame2, text='Voir méta inbox', command=admin_view_inbox_meta, bg=ModernStyle.PANEL, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)
        tk.Button(action_frame2, text='Supprimer message', command=admin_delete_message_from_user, bg=ModernStyle.CARD, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)

        action_frame3 = tk.Frame(right, bg=ModernStyle.BG)
        action_frame3.pack(fill=tk.X, pady=6)
        tk.Button(action_frame3, text='Bannir email', command=admin_ban_email, bg=ModernStyle.ACCENT, fg='white').pack(side=tk.LEFT, padx=6)
        tk.Button(action_frame3, text='Débannir email', command=admin_unban_email, bg=ModernStyle.PANEL, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)
        tk.Button(action_frame3, text='Bannir IP', command=admin_ban_ip, bg=ModernStyle.CARD, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)
        tk.Button(action_frame3, text='Débannir IP', command=admin_unban_ip, bg=ModernStyle.PANEL, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)

        action_frame4 = tk.Frame(right, bg=ModernStyle.BG)
        action_frame4.pack(fill=tk.X, pady=6)
        tk.Button(action_frame4, text='Sauvegarder base', command=admin_backup, bg=ModernStyle.CARD, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)
        tk.Button(action_frame4, text='Restaurer base', command=admin_restore, bg=ModernStyle.CARD, fg=ModernStyle.TEXT).pack(side=tk.LEFT, padx=6)

        tk.Button(right, text='Afficher statistiques', command=lambda: self._admin_show_stats(details_txt), bg=ModernStyle.PANEL, fg=ModernStyle.TEXT).pack(pady=8)

        admin_win.transient(self.root)
        admin_win.grab_set()

    def _admin_show_stats(self, details_txt_widget):
        users = load_users()
        total = len(users)
        total_msgs = sum(len(u.get('inbox', [])) for u in users.values())
        admins = [e for e, uu in users.items() if uu.get('is_admin')]
        bans = load_bans()
        s = {
            'total_users': total,
            'total_messages': total_msgs,
            'admins': admins,
            'banned_emails': bans.get('emails', []),
            'banned_ips': bans.get('ips', [])
        }
        details_txt_widget.configure(state=tk.NORMAL)
        details_txt_widget.delete('1.0', tk.END)
        details_txt_widget.insert(tk.END, json.dumps({'stats': s}, indent=2, ensure_ascii=False))
        details_txt_widget.configure(state=tk.DISABLED)

# -----------------------------
# LANCEMENT
# -----------------------------
if __name__ == '__main__':
    ensure_admin_exists()
    root = tk.Tk()
    root.withdraw()
    # quick splash
    root.after(100, lambda: root.deiconify())
    app = SecureMessengerApp(root)
    root.mainloop()
