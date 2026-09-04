const express = require('express');
const postgres = require('postgres');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Conexão com o PostgreSQL / Supabase
const connectionString = process.env.DATABASE_URL || 'postgresql://postgres.ncrlnceqrbjgrztkclxk:%40G1hh4ej22d@aws-0-us-west-2.pooler.supabase.com:6543/postgres';
const sql = postgres(connectionString, { ssl: 'require' });

// Inicializar tabelas e garantir o Admin padrão
async function inicializarBanco() {
    try {
        await sql`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nome TEXT,
                email TEXT UNIQUE,
                senha TEXT,
                data_expiracao TIMESTAMP,
                is_admin INTEGER DEFAULT 0,
                status TEXT DEFAULT 'ativo'
            )
        `;

        await sql`
            CREATE TABLE IF NOT EXISTS lancamentos (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER,
                tipo TEXT,
                categoria TEXT,
                valor REAL,
                descricao TEXT,
                data_lancamento TEXT,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            )
        `;

        const emailAdmin = 'admin@gmail.com';
        const usuariosExistentes = await sql`SELECT id FROM usuarios WHERE email = ${emailAdmin}`;
        
        if (usuariosExistentes.length === 0) {
            const senhaHash = await bcrypt.hash('1234', 10);
            const dataExpiracao = new Date();
            dataExpiracao.setFullYear(dataExpiracao.getFullYear() + 100);

            await sql`
                INSERT INTO usuarios (nome, email, senha, data_expiracao, is_admin, status) 
                VALUES ('Administrador', ${emailAdmin}, ${senhaHash}, ${dataExpiracao.toISOString()}, 1, 'ativo')
            `;
            console.log('Usuário Administrador criado com sucesso! E-mail: admin@gmail.com / Senha: 1234');
        }
        console.log('Conectado ao PostgreSQL/Supabase com sucesso!');
    } catch (e) {
        console.error('Erro ao inicializar o banco:', e.message);
    }
}

inicializarBanco();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'motoboy_secret_key_99food',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Servir arquivos estáticos da pasta public
app.use(express.static(path.join(__dirname, 'public')));

// Rota raiz para entregar o index.html corretamente
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Rota para verificar sessão atual
app.get('/api/session', async (req, res) => {
    if (req.session.userId) {
        try {
            const usuarios = await sql`SELECT * FROM usuarios WHERE id = ${req.session.userId}`;
            const usuario = usuarios[0];

            if (!usuario) {
                return res.json({ logado: false });
            }
            
            const agora = new Date();
            const expiracao = new Date(usuario.data_expiracao);
            if (usuario.status === 'bloqueado' || (usuario.is_admin === 0 && expiracao < agora)) {
                return res.json({ logado: false, mensagem: 'Conta expirada ou bloqueada.' });
            }

            res.json({
                logado: true,
                nome: usuario.nome,
                email: usuario.email,
                data_expiracao: usuario.data_expiracao,
                is_admin: usuario.is_admin
            });
        } catch (err) {
            res.json({ logado: false });
        }
    } else {
        res.json({ logado: false });
    }
});

// Rota de Cadastro e Login
app.post('/api/auth', async (req, res) => {
    const { acao, nome, email, senha } = req.body;

    if (acao === 'cadastrar') {
        try {
            const senhaHash = await bcrypt.hash(senha, 10);
            const emailAdminMestre = 'admin@gmail.com'; 
            const isAdminUser = (email.toLowerCase() === emailAdminMestre) ? 1 : 0;

            const dataExpiracao = new Date();
            if (isAdminUser === 1) {
                dataExpiracao.setFullYear(dataExpiracao.getFullYear() + 100);
            } else {
                dataExpiracao.setDate(dataExpiracao.getDate() + 3);
            }

            await sql`
                INSERT INTO usuarios (nome, email, senha, data_expiracao, is_admin, status) 
                VALUES (${nome}, ${email}, ${senhaHash}, ${dataExpiracao.toISOString()}, ${isAdminUser}, 'ativo')
            `;

            res.json({ 
                sucesso: true, 
                mensagem: isAdminUser === 1 ? 'Conta de Administrador criada com sucesso!' : 'Cadastro realizado com sucesso! Você ganhou 3 dias de teste grátis.' 
            });
        } catch (e) {
            res.json({ sucesso: false, mensagem: 'E-mail já cadastrado ou inválido!' });
        }
    } else if (acao === 'login') {
        try {
            const usuarios = await sql`SELECT * FROM usuarios WHERE email = ${email}`;
            const usuario = usuarios[0];

            if (!usuario) {
                return res.json({ sucesso: false, mensagem: 'E-mail ou senha incorretos!' });
            }

            if (usuario.status === 'bloqueado') {
                return res.json({ sucesso: false, mensagem: 'Sua conta está bloqueada pelo administrador!' });
            }

            const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
            if (!senhaCorreta) {
                return res.json({ sucesso: false, mensagem: 'E-mail ou senha incorretos!' });
            }

            req.session.userId = usuario.id;
            req.session.nome = usuario.nome;
            req.session.is_admin = usuario.is_admin;
            res.json({ sucesso: true });
        } catch (e) {
            res.status(500).json({ sucesso: false, mensagem: 'Erro interno no servidor.' });
        }
    }
});

// ==========================================
// ROTAS DO PAINEL ADMINISTRADOR (Protegidas)
// ==========================================

function isAdmin(req, res, next) {
    if (req.session && req.session.is_admin === 1) {
        return next();
    }
    return res.status(403).json({ sucesso: false, mensagem: 'Acesso negado. Apenas o administrador mestre.' });
}

app.get('/api/admin/usuarios', isAdmin, async (req, res) => {
    try {
        const rows = await sql`SELECT id, nome, email, data_expiracao, is_admin, status FROM usuarios`;
        res.json(rows);
    } catch (err) {
        res.status(500).json({ erro: err.message });
    }
});

app.post('/api/admin/renovar/:id', isAdmin, async (req, res) => {
    const userId = req.params.id;
    
    try {
        const usuarios = await sql`SELECT data_expiracao FROM usuarios WHERE id = ${userId}`;
        const row = usuarios[0];
        if (!row) return res.status(404).json({ sucesso: false, mensagem: 'Usuário não encontrado.' });

        let baseDate = new Date();
        const dataAtualExp = new Date(row.data_expiracao);
        
        if (dataAtualExp > baseDate) {
            baseDate = dataAtualExp;
        }

        baseDate.setDate(baseDate.getDate() + 30);
        const novaExpiracao = baseDate.toISOString();

        await sql`UPDATE usuarios SET data_expiracao = ${novaExpiracao} WHERE id = ${userId}`;
        res.json({ sucesso: true, mensagem: 'Assinatura renovada com sucesso por 30 dias!' });
    } catch (err) {
        res.status(500).json({ sucesso: false, mensagem: 'Erro ao atualizar.' });
    }
});

// Rota para Bloquear usuário
app.post('/api/admin/bloquear/:id', isAdmin, async (req, res) => {
    const userId = req.params.id;
    try {
        await sql`UPDATE usuarios SET status = 'bloqueado' WHERE id = ${userId}`;
        res.json({ sucesso: true, mensagem: 'Usuário bloqueado com sucesso!' });
    } catch (err) {
        res.status(500).json({ sucesso: false, mensagem: 'Erro ao bloquear usuário' });
    }
});

// Rota para Desbloquear usuário
app.post('/api/admin/desbloquear/:id', isAdmin, async (req, res) => {
    const userId = req.params.id;
    try {
        await sql`UPDATE usuarios SET status = 'ativo' WHERE id = ${userId}`;
        res.json({ sucesso: true, mensagem: 'Usuário desbloqueado com sucesso!' });
    } catch (err) {
        res.status(500).json({ sucesso: false, mensagem: 'Erro ao desbloquear usuário' });
    }
});


app.delete('/api/admin/usuarios/:id', isAdmin, async (req, res) => {
    const userId = req.params.id;

    if (userId == req.session.userId) {
        return res.status(400).json({ sucesso: false, mensagem: 'Você não pode excluir sua própria conta de Administrador Master!' });
    }

    try {
        await sql`DELETE FROM usuarios WHERE id = ${userId}`;
        res.json({ sucesso: true, mensagem: 'Usuário excluído com sucesso!' });
    } catch (err) {
        res.status(500).json({ sucesso: false, mensagem: 'Erro ao excluir usuário.' });
    }
});

// ==========================================

app.get('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/api/dados', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ erro: 'Não autorizado' });

    const userId = req.session.userId;
    const hoje = new Date().toISOString().split('T')[0];

    try {
        const rows = await sql`SELECT * FROM lancamentos WHERE usuario_id = ${userId} ORDER BY data_lancamento DESC, id DESC`;

        let saldo_hoje = 0;
        let ganhos_semana = 0;
        let gastos_semana = 0;
        let ganhos_mes = 0;
        let gastos_mes = 0;

        const mesAtual = hoje.substring(0, 7);

        rows.forEach(item => {
            const valorNum = parseFloat(item.valor) || 0;

            if (item.data_lancamento === hoje) {
                if (item.tipo === 'ganho') saldo_hoje += valorNum;
                if (item.tipo === 'gasto') saldo_hoje -= valorNum;
            }

            if (item.data_lancamento && item.data_lancamento.startsWith(mesAtual)) {
                if (item.tipo === 'ganho') ganhos_mes += valorNum;
                if (item.tipo === 'gasto') gastos_mes += valorNum;
            }

            if (item.tipo === 'ganho') ganhos_semana += valorNum;
            if (item.tipo === 'gasto') gastos_semana += valorNum;
        });

        res.json({
            saldo_hoje,
            ganhos_semana,
            gastos_semana,
            ganhos_mes,
            gastos_mes,
            historico: rows
        });
    } catch (err) {
        console.error("Erro em /api/dados:", err.message);
        res.status(500).json({ erro: 'Erro ao buscar dados' });
    }
});

app.post('/api/lancamentos', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ erro: 'Não autorizado' });

    const { tipo, categoria, valor, descricao, data_lancamento } = req.body;
    const userId = req.session.userId;
    const valorNum = parseFloat(valor.toString().replace(',', '.'));

    try {
        await sql`
            INSERT INTO lancamentos (usuario_id, tipo, categoria, valor, descricao, data_lancamento) 
            VALUES (${userId}, ${tipo}, ${categoria}, ${valorNum}, ${descricao}, ${data_lancamento})
        `;
        res.json({ sucesso: true });
    } catch (err) {
        res.status(500).json({ sucesso: false });
    }
});

app.delete('/api/lancamentos/:id', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ erro: 'Não autorizado' });

    const id = req.params.id;
    const userId = req.session.userId;

    try {
        await sql`DELETE FROM lancamentos WHERE id = ${id} AND usuario_id = ${userId}`;
        res.json({ sucesso: true });
    } catch (err) {
        res.status(500).json({ erro: 'Erro ao excluir' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});