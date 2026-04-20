# 🔐 GRE-CorpVault

**Controle de Senhas Corporativas** — aplicação web com backend real, banco de dados central e acesso multiusuário.

---

## 🏗️ Arquitetura

```
gre-corpvault/
├── server/
│   └── index.js        ← Backend (Node.js + Express + SQLite)
├── public/
│   └── index.html      ← Frontend (HTML/JS puro, sem frameworks)
├── package.json
├── .env.example
└── README.md
```

**Stack:**
- **Backend:** Node.js + Express
- **Banco:** SQLite via `better-sqlite3` (arquivo local, zero configuração)
- **Criptografia:** AES-256 (crypto-js) para senhas de colaboradores
- **Autenticação:** Sessões + bcrypt para senhas de login
- **Segurança:** helmet, httpOnly cookies, rotas protegidas

---

## 🚀 Como rodar localmente

### 1. Pré-requisitos
- **Node.js 18+** instalado → [nodejs.org](https://nodejs.org)
- Git (opcional)

### 2. Instalar dependências
```bash
cd gre-corpvault
npm install
```

### 3. Configurar variáveis de ambiente (recomendado)
```bash
cp .env.example .env
```
Edite o `.env` e troque as chaves:
```
ENC_KEY=sua-chave-secreta-longa-aqui-minimo-32-caracteres
SESSION_SECRET=outro-segredo-longo-aqui
```

> ⚠️ **IMPORTANTE:** Se você mudar o `ENC_KEY` depois que já houver dados no banco, as senhas existentes não conseguirão ser descriptografadas. Defina antes de começar a usar.

### 4. Iniciar o servidor
```bash
npm start
```

Acesse: **http://localhost:3000**

### 5. Login padrão
| Campo | Valor |
|-------|-------|
| Usuário | `admin` |
| Senha | `admin123` |

> ⚠️ **Troque a senha do admin imediatamente após o primeiro login!**
> Menu lateral → "Trocar minha senha"

---

## 👥 Multiusuário

- O admin pode criar outros usuários pelo menu lateral → "Gerenciar usuários"
- Dois perfis: **admin** (cria/remove usuários) e **user** (acesso normal)
- Todos os usuários enxergam os mesmos dados em tempo real (após reload)
- Cada usuário tem sua própria sessão (logout independente)

---

## 🔒 Segurança implementada

| Camada | Mecanismo |
|--------|-----------|
| Senhas de login | bcrypt (hash seguro, nunca texto puro) |
| Senhas de colaboradores | AES-256 (criptografadas no banco) |
| Sessões | httpOnly cookies, 8h de expiração |
| Headers HTTP | helmet (X-Frame-Options, CSP, etc.) |
| Rotas | Todas as rotas de dados exigem autenticação |
| Admin | Endpoints de usuário exigem perfil admin |

---

## ☁️ Deploy gratuito (Railway — recomendado)

Railway é a opção mais simples para hospedar Node.js + SQLite:

1. Crie conta em [railway.app](https://railway.app)
2. Novo projeto → "Deploy from GitHub repo"
3. Faça push do projeto para um repositório GitHub
4. Configure as variáveis de ambiente no painel do Railway:
   - `ENC_KEY` → sua chave secreta
   - `SESSION_SECRET` → outro segredo
   - `NODE_ENV` → `production`
5. Railway detecta o `package.json` e roda `npm start` automaticamente

> **Nota sobre SQLite em produção:** O Railway tem storage efêmero — o banco é resetado a cada deploy. Para persistência real, considere usar o add-on **PostgreSQL do Railway** e adaptar o `server/index.js` para usar `pg` em vez de `better-sqlite3`.

### Alternativa: Render.com
1. [render.com](https://render.com) → New Web Service
2. Conecte o repositório GitHub
3. Build command: `npm install`
4. Start command: `npm start`
5. Configure as variáveis de ambiente

---

## 🔧 Comandos úteis

```bash
npm start          # inicia o servidor (produção)
npm run dev        # inicia com auto-reload (requer nodemon)
```

---

## 🗃️ Banco de dados

O banco SQLite é criado automaticamente em `server/vault.db` na primeira execução.
Os dados iniciais (colaboradores do seed) são importados automaticamente se o banco estiver vazio.

Para resetar tudo:
```bash
rm server/vault.db
npm start   # recria o banco e o admin padrão
```

---

## 📡 API REST

| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Usuário atual |
| POST | `/api/auth/change-password` | Trocar senha |
| GET | `/api/employees` | Listar colaboradores |
| POST | `/api/employees` | Criar colaborador |
| PUT | `/api/employees/:id` | Editar colaborador |
| DELETE | `/api/employees/:id` | Remover colaborador |
| GET | `/api/users` | Listar usuários (admin) |
| POST | `/api/users` | Criar usuário (admin) |
| DELETE | `/api/users/:id` | Remover usuário (admin) |
