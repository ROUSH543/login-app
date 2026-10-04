const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

const SESSION_SECRET =
  process.env.SESSION_SECRET || "dev-only-change-this-session-secret";

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    name: "site.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 8
    }
  })
);

async function ensureDatabase() {
  await fs.mkdir(DATA_DIR, { recursive: true });

  let users = [];
  try {
    const raw = await fs.readFile(USERS_FILE, "utf8");
    users = JSON.parse(raw);
    if (!Array.isArray(users)) users = [];
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const adminExists = users.some(
    (user) => String(user.email).toLowerCase() === "admin@site.com"
  );

  if (!adminExists) {
    const senhaHash = await bcrypt.hash("admin123", 12);
    users.push({
      id: crypto.randomUUID(),
      email: "admin@site.com",
      senhaHash,
      role: "admin",
      criadoEm: new Date().toISOString()
    });
    await saveUsers(users);
  } else {
    await saveUsers(users);
  }
}

async function loadUsers() {
  const raw = await fs.readFile(USERS_FILE, "utf8");
  const users = JSON.parse(raw);
  return Array.isArray(users) ? users : [];
}

async function saveUsers(users) {
  await fs.writeFile(
    USERS_FILE,
    JSON.stringify(users, null, 2) + "\n",
    "utf8"
  );
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    criadoEm: user.criadoEm
  };
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Não autenticado."
    });
  }
  next();
}

async function getCurrentUser(req) {
  if (!req.session.userId) return null;

  const users = await loadUsers();
  return (
    users.find((user) => user.id === req.session.userId) || null
  );
}

async function requireAdmin(req, res, next) {
  try {
    const user = await getCurrentUser(req);

    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: "Não autenticado." });
    }

    if (user.role !== "admin") {
      return res.status(403).json({ error: "Acesso restrito ao administrador." });
    }

    req.currentUser = user;
    next();
  } catch (error) {
    next(error);
  }
}

app.get("/api/auth/me", async (req, res, next) => {
  try {
    const user = await getCurrentUser(req);

    if (!user) {
      return res.json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "Informe um email válido." });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "A senha deve ter pelo menos 6 caracteres." });
    }

    const users = await loadUsers();

    const exists = users.some((user) => user.email === email);
    if (exists) {
      return res.status(409).json({ error: "Este email já está cadastrado." });
    }

    const senhaHash = await bcrypt.hash(password, 12);

    const newUser = {
      id: crypto.randomUUID(),
      email,
      senhaHash,
      role: "user",
      criadoEm: new Date().toISOString()
    };

    users.push(newUser);
    await saveUsers(users);

    req.session.userId = newUser.id;

    res.status(201).json({
      message: "Cadastro realizado com sucesso.",
      user: publicUser(newUser)
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const users = await loadUsers();
    const user = users.find((item) => item.email === email);

    if (!user) {
      return res.status(401).json({ error: "Email ou senha inválidos." });
    }

    const passwordMatches = await bcrypt.compare(password, user.senhaHash);

    if (!passwordMatches) {
      return res.status(401).json({ error: "Email ou senha inválidos." });
    }

    req.session.userId = user.id;

    res.json({
      message: "Login realizado com sucesso.",
      user: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("site.sid");
    res.json({ message: "Logout realizado com sucesso." });
  });
});

app.get("/api/users", requireAdmin, async (req, res, next) => {
  try {
    const users = await loadUsers();

    // Nunca enviar senhaHash ao frontend.
    res.json({
      users: users.map(publicUser)
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/protected/dashboard", requireAuth, async (req, res, next) => {
  try {
    const user = await getCurrentUser(req);

    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: "Sessão inválida." });
    }

    res.json({
      user: publicUser(user),
      message: "Área protegida carregada com sucesso."
    });
  } catch (error) {
    next(error);
  }
});

app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/register.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.get("/dashboard.html", async (req, res, next) => {
  try {
    const user = await getCurrentUser(req);
    if (!user) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
  } catch (error) {
    next(error);
  }
});

app.get("/admin.html", async (req, res, next) => {
  try {
    const user = await getCurrentUser(req);
    if (!user) return res.redirect("/");
    if (user.role !== "admin") return res.redirect("/dashboard.html");
    res.sendFile(path.join(__dirname, "public", "admin.html"));
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => {
  res.redirect("/");
});

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);

  res.status(500).json({
    error: "Erro interno do servidor."
  });
});

ensureDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Servidor rodando em http://localhost:${PORT}`);
      console.log("Admin padrão: admin@site.com / admin123");
    });
  })
  .catch((error) => {
    console.error("Falha ao iniciar:", error);
    process.exit(1);
  });
