// Affiche les sections selon l'état de connexion
function showSection(section) {
  document.getElementById('auth').style.display = section === 'auth' ? 'block' : 'none';
  document.getElementById('messagerie').style.display = section === 'messagerie' ? 'block' : 'none';
}

// Affiche un message de statut
function setStatus(msg, color='#2ecc71') {
  const status = document.getElementById('status');
  status.textContent = msg;
  status.style.color = color;
}

// Gestion de la connexion
document.getElementById('loginForm').onsubmit = async function(e) {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value;
  const code = document.getElementById('loginCode').value;
  const res = await fetch('/login', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({email, code})
  });
  const data = await res.json();
  if (data.success) {
    showSection('messagerie');
    setStatus('Connecté !');
    loadInbox();
    window.sessionStorage.setItem('user', email);
  } else {
    setStatus(data.message, '#e74c3c');
  }
};

// Gestion de l'inscription
document.getElementById('registerForm').onsubmit = async function(e) {
  e.preventDefault();
  const first = document.getElementById('registerFirst').value;
  const last = document.getElementById('registerLast').value;
  const email = document.getElementById('registerEmail').value;
  const code = document.getElementById('registerCode').value;
  const res = await fetch('/register', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({first, last, email, code})
  });
  const data = await res.json();
  if (data.success) {
    setStatus('Compte créé ! Connectez-vous.');
  } else {
    setStatus(data.message, '#e74c3c');
  }
};

// Envoi de message
document.getElementById('sendForm').onsubmit = async function(e) {
  e.preventDefault();
  const to = document.getElementById('sendTo').value;
  const content = document.getElementById('sendContent').value;
  const from = window.sessionStorage.getItem('user');
  const res = await fetch('/send_message', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({from, to, content})
  });
  const data = await res.json();
  if (data.success) {
    setStatus('Message envoyé !');
    loadInbox();
    document.getElementById('sendContent').value = '';
  } else {
    setStatus(data.message, '#e74c3c');
  }
};

// Chargement de la boîte de réception
async function loadInbox() {
  const user = window.sessionStorage.getItem('user');
  const res = await fetch('/inbox?email=' + encodeURIComponent(user));
  const data = await res.json();
  const inbox = document.getElementById('inbox');
  inbox.innerHTML = '';
  data.messages.forEach(msg => {
    const li = document.createElement('li');
    li.textContent = `De ${msg.from} : ${msg.content}`;
    inbox.appendChild(li);
  });
}

// Au chargement, affiche la bonne section
window.onload = function() {
  if (window.sessionStorage.getItem('user')) {
    showSection('messagerie');
    loadInbox();
  } else {
    showSection('auth');
  }
};