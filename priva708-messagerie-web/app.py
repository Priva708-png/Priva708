from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os

app = Flask(__name__)
CORS(app)

DATA_FILE = 'users.json'

def load_users():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    users = load_users()
    email = data['email']
    if email in users:
        return jsonify({'success': False, 'message': 'Email déjà utilisé.'})
    users[email] = {
        'first': data['first'],
        'last': data['last'],
        'code': data['code'],  # Pour simplifier, pas de hash ici (à améliorer !)
        'inbox': []
    }
    save_users(users)
    return jsonify({'success': True})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    users = load_users()
    email = data['email']
    code = data['code']
    if email not in users or users[email]['code'] != code:
        return jsonify({'success': False, 'message': 'Identifiants incorrects.'})
    return jsonify({'success': True})

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    users = load_users()
    to = data['to']
    from_ = data['from']
    content = data['content']
    if to not in users:
        return jsonify({'success': False, 'message': 'Destinataire inconnu.'})
    users[to]['inbox'].append({'from': from_, 'content': content})
    save_users(users)
    return jsonify({'success': True})

@app.route('/inbox')
def inbox():
    email = request.args.get('email')
    users = load_users()
    if email not in users:
        return jsonify({'messages': []})
    return jsonify({'messages': users[email]['inbox']})

if __name__ == '__main__':
    app.run(debug=True)