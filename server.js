const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt'); // Para proteger senhas
const app = express();

const USERS_FILE = path.join(__dirname, 'users.json');

// Configuração de sessão
app.use(session({
    secret: 'chave-secreta',
    resave: false,
    saveUninitialized: true,
}));

app.use(express.json());
app.use(express.static('public'));

// Função para carregar usuários
function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    }
    return JSON.parse(fs.readFileSync(USERS_FILE));
}

// Função para salvar usuários
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Rota de cadastro
app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Usuário e senha são obrigatórios.' });
    }

    const users = loadUsers();
    if (users.find(user => user.username === username)) {
        return res.status(409).json({ message: 'Usuário já existe.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Criptografando a senha
    users.push({ username, password: hashedPassword });
    saveUsers(users);
    res.status(201).json({ message: 'Usuário cadastrado com sucesso.' });
});

// Rota de login
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = username;
        res.status(200).json({ message: 'Login bem-sucedido.' });
    } else {
        res.status(401).json({ message: 'Usuário ou senha inválidos.' });
    }
});

// Middleware de autenticação
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login.html');
    }
}

// Rota protegida
app.get('/admin.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Rota para login
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Rota para cadastro
app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Inicializar o servidor
app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
