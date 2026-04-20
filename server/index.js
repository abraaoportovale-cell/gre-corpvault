/**
 * GRE-CorpVault — Backend
 * Node.js + Express + sql.js (SQLite via WASM — zero compilação nativa)
 * Senhas de colaboradores criptografadas com AES (crypto-js)
 * Autenticação via sessão + bcrypt
 */

const express   = require('express');
const session   = require('express-session');
const bcrypt    = require('bcryptjs');
const CryptoJS  = require('crypto-js');
const initSqlJs = require('sql.js');
const helmet    = require('helmet');
const cors      = require('cors');
const path      = require('path');
const fs        = require('fs');

const app     = express();
const PORT    = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'vault.db');

const ENC_KEY = process.env.ENC_KEY || 'GRE-CorpVault-Secret-Key-2026!@#';

let db;

function saveToDisk() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

async function initDb() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
    console.log('📂 Banco carregado:', DB_PATH);
  } else {
    db = new SQL.Database();
    console.log('📂 Novo banco criado:', DB_PATH);
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      team TEXT NOT NULL,
      nb TEXT DEFAULT '',
      cel TEXT DEFAULT '',
      pin TEXT DEFAULT '',
      ms TEXT DEFAULT '',
      wifi TEXT DEFAULT '',
      obs TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);
  saveToDisk();
  if (!queryOne('SELECT id FROM users WHERE username = ?', ['admin'])) {
    const hash = bcrypt.hashSync('admin123', 10);
    run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ['admin', hash, 'admin']);
    saveToDisk();
    console.log('✅ Admin criado → login: admin | senha: admin123');
  }
  const { n } = queryOne('SELECT COUNT(*) as n FROM employees', []);
  if (n === 0) { seedData(); saveToDisk(); }
}

function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}
function queryOne(sql, params = []) { return queryAll(sql, params)[0] || null; }
function run(sql, params = []) { db.run(sql, params); }
function lastInsertId() { return queryOne('SELECT last_insert_rowid() as id', []).id; }

const ENCRYPTED_FIELDS = ['nb', 'pin', 'ms'];
function encrypt(text) { if (!text) return ''; return CryptoJS.AES.encrypt(String(text), ENC_KEY).toString(); }
function decrypt(cipher) { if (!cipher) return ''; try { return CryptoJS.AES.decrypt(cipher, ENC_KEY).toString(CryptoJS.enc.Utf8) || ''; } catch { return ''; } }
function encryptEmp(data) { const out = { ...data }; for (const f of ENCRYPTED_FIELDS) if (out[f] !== undefined) out[f] = encrypt(out[f]); return out; }
function decryptEmp(row) { if (!row) return null; const out = { ...row }; for (const f of ENCRYPTED_FIELDS) if (out[f] !== undefined) out[f] = decrypt(out[f]); return out; }

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'vault-session-secret-2026', resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: false, maxAge: 8 * 60 * 60 * 1000 } }));
app.use(express.static(path.join(__dirname, '../public')));

function requireAuth(req, res, next) { if (!req.session?.userId) return res.status(401).json({ error: 'Não autenticado.' }); next(); }
function requireAdmin(req, res, next) { if (req.session?.role !== 'admin') return res.status(403).json({ error: 'Acesso restrito a admins.' }); next(); }

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Preencha todos os campos.' });
  const user = queryOne('SELECT * FROM users WHERE username = ?', [username.trim()]);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
  req.session.userId = user.id; req.session.username = user.username; req.session.role = user.role;
  res.json({ ok: true, username: user.username, role: user.role });
});
app.post('/api/auth/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/api/auth/me', (req, res) => { if (!req.session?.userId) return res.status(401).json({ authenticated: false }); res.json({ authenticated: true, username: req.session.username, role: req.session.role }); });
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Nova senha deve ter pelo menos 6 caracteres.' });
  const user = queryOne('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  if (!bcrypt.compareSync(currentPassword, user.password)) return res.status(401).json({ error: 'Senha atual incorreta.' });
  run('UPDATE users SET password = ? WHERE id = ?', [bcrypt.hashSync(newPassword, 10), req.session.userId]);
  saveToDisk(); res.json({ ok: true });
});

app.get('/api/users', requireAuth, requireAdmin, (_req, res) => { res.json(queryAll('SELECT id, username, role, created_at FROM users ORDER BY id')); });
app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || password.length < 6) return res.status(400).json({ error: 'Dados inválidos.' });
  try { run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username.trim(), bcrypt.hashSync(password, 10), role === 'admin' ? 'admin' : 'user']); saveToDisk(); res.json({ ok: true, id: lastInsertId() }); }
  catch { res.status(400).json({ error: 'Usuário já existe.' }); }
});
app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.session.userId) return res.status(400).json({ error: 'Não é possível excluir o próprio usuário.' });
  run('DELETE FROM users WHERE id = ?', [id]); saveToDisk(); res.json({ ok: true });
});

app.get('/api/employees', requireAuth, (_req, res) => { res.json(queryAll('SELECT * FROM employees ORDER BY team, name').map(decryptEmp)); });
app.post('/api/employees', requireAuth, (req, res) => {
  const { name, team, nb='', cel='', pin='', ms='', wifi='', obs='' } = req.body;
  if (!name || !team) return res.status(400).json({ error: 'Nome e time são obrigatórios.' });
  const d = encryptEmp({ name: name.trim(), team, nb, cel, pin, ms, wifi, obs });
  run('INSERT INTO employees (name,team,nb,cel,pin,ms,wifi,obs) VALUES (?,?,?,?,?,?,?,?)', [d.name, d.team, d.nb, d.cel, d.pin, d.ms, d.wifi, d.obs]);
  const id = lastInsertId(); saveToDisk();
  res.json(decryptEmp(queryOne('SELECT * FROM employees WHERE id = ?', [id])));
});
app.put('/api/employees/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const ex = queryOne('SELECT * FROM employees WHERE id = ?', [id]);
  if (!ex) return res.status(404).json({ error: 'Não encontrado.' });
  const { name, team, nb='', cel='', pin='', ms='', wifi='', obs='' } = req.body;
  const d = encryptEmp({ name: (name||'').trim()||ex.name, team: team||ex.team, nb, cel, pin, ms, wifi, obs });
  run(`UPDATE employees SET name=?,team=?,nb=?,cel=?,pin=?,ms=?,wifi=?,obs=?,updated_at=datetime('now') WHERE id=?`, [d.name, d.team, d.nb, d.cel, d.pin, d.ms, d.wifi, d.obs, id]);
  saveToDisk(); res.json(decryptEmp(queryOne('SELECT * FROM employees WHERE id = ?', [id])));
});
app.delete('/api/employees/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!queryOne('SELECT id FROM employees WHERE id = ?', [id])) return res.status(404).json({ error: 'Não encontrado.' });
  run('DELETE FROM employees WHERE id = ?', [id]); saveToDisk(); res.json({ ok: true });
});

function seedData() {
  const SEED = [
    { name:'Anna Carolina Arantes Moreira', team:'intelcomer', nb:'Anna@2026!!', cel:'', pin:'', ms:'Arantes@2026!!', wifi:'', obs:'' },
    { name:'Carolina Valeria dos Santos', team:'intelcomer', nb:'Porto@Vale', cel:'(12) 2018-1021', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Vitoria da Silva Vasques', team:'intelcomer', nb:'Porto@Vale', cel:'12 2018-1009', pin:'2026', ms:'', wifi:'', obs:'' },
    { name:'Nicolas Ferreira Montagna', team:'intelcomer', nb:'Porto@Vale', cel:'1220181012', pin:'2026', ms:'', wifi:'', obs:'' },
    { name:'Kaisa Caroline de Freitas Martins', team:'intelcomer', nb:'Porto@Vale', cel:'12 2018-1029', pin:'2026', ms:'', wifi:'', obs:'' },
    { name:'Renan Intrieri Fiebig Machado', team:'intelcomer', nb:'Porto@Vale', cel:'(12)2018-1009', pin:'2026', ms:'', wifi:'', obs:'' },
    { name:'Evellyn Vitoria dos Reis Melo', team:'intelcomer', nb:'Porto@Vale', cel:'12 2018-0956', pin:'2026', ms:'', wifi:'', obs:'' },
    { name:'Marcio da Silva Nogaroto', team:'intelcomer', nb:'Porto@Vale', cel:'12 3600-2690', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Pietra Isabelle Lopes da Silva', team:'intelcomer', nb:'Porto@Vale', cel:'(12) 2018-0957', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Livia Maria Neves Ribeiro', team:'intelcomer', nb:'Porto@Vale', cel:'(12) 2018-1021', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Leonardo Cavalcante Tavares Beato', team:'intelcomer', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Igor de Oliveira Duarte', team:'intelcomer', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Arthur Nicolas da Silva Bomfim', team:'intelcomer', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Melyssa Costa', team:'intelcomer', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Maria Eduarda Goncalves Teixeira', team:'posvenda', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Regiane Ponciano dos Santos Souza', team:'posvenda', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Rafaela Morais da Silva Faria', team:'posvenda', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Bruna Fernanda da Silva Santos', team:'posvenda', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Stephane dos Santos Soares', team:'posvenda', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Tânia (Pós-Venda)', team:'posvenda', nb:'', cel:'1858', pin:'', ms:'', wifi:'', obs:'Tempo Pós-Venda Baju' },
    { name:'Número PV-1', team:'posvenda', nb:'', cel:'12 3042-6017', pin:'', ms:'', wifi:'Validação Wi-Fi1: 103625 | Validação Wi-Fi2: 308125', obs:'' },
    { name:'Número PV-2', team:'posvenda', nb:'', cel:'12 3042-8617', pin:'', ms:'', wifi:'Validação Wi-Fi1: 703625', obs:'' },
    { name:'Gabriela Karla Leonardo do Carmo', team:'cobranca', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Maria Fernanda Alves dos Santos', team:'cobranca', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Hanally Henrique de Oliveira', team:'cobranca', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Ana Carolina de Andrade', team:'cobranca', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Tânia (Cobrança)', team:'cobranca', nb:'', cel:'1858', pin:'', ms:'', wifi:'', obs:'Tempo Cobrança Baju' },
    { name:'Bruna Santos (Cobr)', team:'cobranca', nb:'Porto@vale', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Loana', team:'cobranca', nb:'@yorksvale', cel:'', pin:'', ms:'', wifi:'WhatsApp: 541218', obs:'' },
    { name:'Número Cobrança', team:'cobranca', nb:'', cel:'12 3042-1083', pin:'', ms:'', wifi:'Validação Wi-Fi1: 290812', obs:'' },
    { name:'Número Cobrança-2', team:'cobranca', nb:'', cel:'12 2013-6481', pin:'', ms:'', wifi:'Validação Wi-Fi2: 290812', obs:'' },
    { name:'Número Nagrane (Cobr)', team:'cobranca', nb:'', cel:'12 3042-5313', pin:'', ms:'', wifi:'Validação Wi-Fi1: 125014', obs:'' },
    { name:'Sara Bezerra Santos', team:'poscontemp', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Pedro Paulo Diniz Sousa', team:'poscontemp', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Dominik Rocha Dias', team:'poscontemp', nb:'Porto@vale', cel:'1703 - PN 298098', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Brunna (Pós-Contemp)', team:'poscontemp', nb:'Porto@Vale29', cel:'12 2680 - PN 258098', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Julia Degam Vargas', team:'backoffice', nb:'Porto@Vale', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Mayara dos Santos Paulino', team:'backoffice', nb:'Porto!!', cel:'1010 | PN 140425', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Leticia Juvelina Monteiro Sun', team:'backoffice', nb:'Porto@Vale', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Marcelo Lopes Sampaio Moreira', team:'backoffice', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Luana Pereira de Paula', team:'backoffice', nb:'', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Rosalani Oliveira', team:'backoffice', nb:'Porto@vale', cel:'Não possui celular da empresa', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Dayanne Martins', team:'backoffice', nb:'Porto@Vale', cel:'1808', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Erica', team:'backoffice', nb:'Porto@vale', cel:'1103', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Abrãao', team:'backoffice', nb:'Porto@1616', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Jéssica Camilo Batalha', team:'backoffice', nb:'Jes@26!', cel:'12 2018-2157', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Melyssa', team:'backoffice', nb:'Eagles@25!!', cel:'', pin:'', ms:'', wifi:'', obs:'' },
    { name:'Ana Carolina (JAC)', team:'backoffice', nb:'15Joey/k34', cel:'', pin:'', ms:'', wifi:'', obs:'COMPUTADORES JAC' },
    { name:'Hanessaly (JAC)', team:'backoffice', nb:'Porto@Vale', cel:'', pin:'', ms:'', wifi:'', obs:'COMPUTADORES JAC' },
    { name:'Gabriela (JAC)', team:'backoffice', nb:'15Joey/k34', cel:'', pin:'', ms:'', wifi:'', obs:'COMPUTADORES JAC' },
    { name:'Nathaela (JAC)', team:'backoffice', nb:'Porto@Vale', cel:'', pin:'', ms:'', wifi:'', obs:'COMPUTADORES JAC' },
    { name:'Maria Fernanda (JAC)', team:'backoffice', nb:'Porto@Vale', cel:'', pin:'', ms:'', wifi:'Senha: Sem senha', obs:'COMPUTADORES JAC' },
    { name:'Regiane (JAC)', team:'backoffice', nb:'Porto@Vale', cel:'', pin:'', ms:'', wifi:'', obs:'COMPUTADORES JAC' },
    { name:'Stephanie (JAC)', team:'backoffice', nb:'15Joey/k34', cel:'', pin:'', ms:'', wifi:'', obs:'COMPUTADORES JAC' },
    { name:'Maria Eduarda (JAC)', team:'backoffice', nb:'Porto@Vale', cel:'', pin:'', ms:'', wifi:'', obs:'COMPUTADORES JAC' },
  ];
  for (const r of SEED) {
    const d = encryptEmp(r);
    run('INSERT INTO employees (name,team,nb,cel,pin,ms,wifi,obs) VALUES (?,?,?,?,?,?,?,?)', [d.name, d.team, d.nb, d.cel, d.pin, d.ms, d.wifi, d.obs]);
  }
  console.log(`✅ ${SEED.length} colaboradores importados.`);
}

app.get('*', (_req, res) => { res.sendFile(path.join(__dirname, '../public/index.html')); });

initDb().then(() => {
  app.listen(PORT, () => { console.log(`\n🔐 GRE-CorpVault → http://localhost:${PORT}\n`); });
}).catch(err => { console.error('❌ Erro fatal:', err); process.exit(1); });
