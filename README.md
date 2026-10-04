# Sistema de Login com Express + JSON

Projeto educacional com:

- `index.html` — login
- `register.html` — cadastro
- `dashboard.html` — área protegida
- `admin.html` — painel administrativo
- Express + express-session
- bcryptjs para hash de senha
- `data/users.json` como armazenamento local

## Como executar

1. Instale Node.js (LTS).
2. Abra o terminal na pasta do projeto.
3. Execute:

```bash
npm install
npm start
```

4. Acesse:

```text
http://localhost:3000
```

## Admin padrão

Na primeira execução, o servidor cria:

- Email: `admin@site.com`
- Senha: `admin123`
- Role: `admin`

A senha é armazenada no JSON somente como hash bcrypt.

## Observação de segurança

Este projeto é apropriado para aprendizado/local. Para produção, troque o `SESSION_SECRET`, use HTTPS, um store de sessão persistente (em vez do MemoryStore padrão) e um banco de dados apropriado.
