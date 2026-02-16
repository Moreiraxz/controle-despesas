require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const { init, get, all, run } = require("./db");
const { auth, requireAdmin } = require("./middlewareAuth");

const app = express();
app.use(express.json());

// Libera o front (Live Server)
app.use(cors({ origin: true, credentials: true }));

// ✅ health check (para não aparecer “Não foi possível obter /”)
app.get("/", (req, res) => {
  res.send("✅ API online. Use /api/...");
});

// ====== AUTH ======
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Dados inválidos" });
  }

  const user = await get("SELECT * FROM users WHERE email = ?", [email]);
  if (!user) return res.status(401).json({ error: "Credenciais inválidas" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });

  // ✅ token continua simples, mas o middleware vai buscar dados no banco
  const token = jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      nome: user.nome,
      role: user.role,
      empresa_id: user.empresa_id
    }
  });
});

app.get("/api/auth/me", auth, async (req, res) => {
  res.json({ user: req.user });
});

// =======================================================
// ✅ USUÁRIOS (ADMIN) — CADASTRAR / LISTAR / EDITAR / EXCLUIR
// =======================================================

// Listar usuários da mesma empresa
app.get("/api/users", auth, requireAdmin, async (req, res) => {
  const rows = await all(
    "SELECT id, nome, email, role, created_at FROM users WHERE empresa_id = ? ORDER BY id DESC",
    [req.user.empresa_id]
  );
  res.json({ users: rows });
});

// Criar usuário (na mesma empresa do admin)
app.post("/api/users", auth, requireAdmin, async (req, res) => {
  const nome = (req.body?.nome || "").trim();
  const email = (req.body?.email || "").trim().toLowerCase();
  const password = (req.body?.password || "").trim();
  const role = (req.body?.role || "user").trim();

  if (!nome || !email || !password) {
    return res.status(400).json({ error: "Nome, e-mail e senha são obrigatórios" });
  }

  if (password.length < 4) {
    return res.status(400).json({ error: "A senha deve ter no mínimo 4 caracteres" });
  }

  const roleFinal = (role === "admin") ? "admin" : "user";

  const exists = await get("SELECT id FROM users WHERE email = ?", [email]);
  if (exists) return res.status(400).json({ error: "Este e-mail já está cadastrado" });

  const hash = await bcrypt.hash(password, 10);

  await run(
    "INSERT INTO users(nome, email, password_hash, role, empresa_id) VALUES(?,?,?,?,?)",
    [nome, email, hash, roleFinal, req.user.empresa_id]
  );

  res.json({ ok: true });
});

// Editar usuário (nome/role) — mesma empresa
app.put("/api/users/:id", auth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const nome = (req.body?.nome || "").trim();
  const role = (req.body?.role || "").trim();

  if (!id) return res.status(400).json({ error: "ID inválido" });
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });

  const roleFinal = (role === "admin") ? "admin" : "user";

  // só altera se for da mesma empresa
  const target = await get(
    "SELECT id FROM users WHERE id = ? AND empresa_id = ?",
    [id, req.user.empresa_id]
  );
  if (!target) return res.status(404).json({ error: "Usuário não encontrado" });

  await run(
    "UPDATE users SET nome = ?, role = ? WHERE id = ? AND empresa_id = ?",
    [nome, roleFinal, id, req.user.empresa_id]
  );

  res.json({ ok: true });
});

// Excluir usuário — mesma empresa (não deixa excluir a si mesmo)
app.delete("/api/users/:id", auth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: "ID inválido" });

  if (id === req.user.id) {
    return res.status(400).json({ error: "Você não pode excluir o próprio usuário" });
  }

  await run(
    "DELETE FROM users WHERE id = ? AND empresa_id = ?",
    [id, req.user.empresa_id]
  );

  res.json({ ok: true });
});

// =======================================================
// ✅ CADASTROS AUXILIARES (AGORA POR EMPRESA, NÃO POR USER)
// =======================================================

async function listCadastro(table, empresaId) {
  return all(
    `SELECT id, nome FROM ${table} WHERE empresa_id = ? ORDER BY nome ASC`,
    [empresaId]
  );
}

async function addCadastro(table, empresaId, userId, nome) {
  await run(
    `INSERT OR IGNORE INTO ${table}(empresa_id, user_id, nome) VALUES(?,?,?)`,
    [empresaId, userId, nome]
  );
}

async function delCadastro(table, empresaId, id) {
  await run(
    `DELETE FROM ${table} WHERE empresa_id = ? AND id = ?`,
    [empresaId, id]
  );
}

app.get("/api/cadastros", auth, async (req, res) => {
  const empresaId = req.user.empresa_id;
  const responsaveis = await listCadastro("cad_responsaveis", empresaId);
  const categorias = await listCadastro("cad_categorias", empresaId);
  const locais = await listCadastro("cad_locais", empresaId);
  res.json({ responsaveis, categorias, locais });
});

app.post("/api/cadastros/responsaveis", auth, async (req, res) => {
  const nome = (req.body?.nome || "").trim();
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });

  await addCadastro("cad_responsaveis", req.user.empresa_id, req.user.id, nome);
  res.json({ ok: true });
});

app.post("/api/cadastros/categorias", auth, async (req, res) => {
  const nome = (req.body?.nome || "").trim();
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });

  await addCadastro("cad_categorias", req.user.empresa_id, req.user.id, nome);
  res.json({ ok: true });
});

app.post("/api/cadastros/locais", auth, async (req, res) => {
  const nome = (req.body?.nome || "").trim();
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });

  await addCadastro("cad_locais", req.user.empresa_id, req.user.id, nome);
  res.json({ ok: true });
});

app.delete("/api/cadastros/:tipo/:id", auth, async (req, res) => {
  const { tipo, id } = req.params;

  const map = {
    responsaveis: "cad_responsaveis",
    categorias: "cad_categorias",
    locais: "cad_locais",
  };

  const table = map[tipo];
  if (!table) return res.status(400).json({ error: "Tipo inválido" });

  await delCadastro(table, req.user.empresa_id, Number(id));
  res.json({ ok: true });
});

app.put("/api/cadastros/:tipo/:id", auth, async (req, res) => {
  const { tipo, id } = req.params;
  const nome = (req.body?.nome || "").trim();
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });

  const map = {
    responsaveis: "cad_responsaveis",
    categorias: "cad_categorias",
    locais: "cad_locais",
  };

  const table = map[tipo];
  if (!table) return res.status(400).json({ error: "Tipo inválido" });

  await run(
    `UPDATE ${table} SET nome = ? WHERE empresa_id = ? AND id = ?`,
    [nome, req.user.empresa_id, Number(id)]
  );

  res.json({ ok: true });
});

// =======================================================
// ✅ DESPESAS (AGORA POR EMPRESA, NÃO POR USER)
// =======================================================

app.post("/api/despesas", auth, async (req, res) => {
  const empresaId = req.user.empresa_id;
  const userId = req.user.id;

  const { data, valor, responsavel, categoria, descricao, local } = req.body || {};

  if (!data || !responsavel || !categoria || !local) {
    return res.status(400).json({ error: "Campos obrigatórios faltando" });
  }

  const v = Number(valor);
  if (!Number.isFinite(v) || v <= 0) {
    return res.status(400).json({ error: "Valor inválido" });
  }

  await run(
    `INSERT INTO despesas(empresa_id, user_id, data, valor, responsavel, categoria, descricao, local)
     VALUES(?,?,?,?,?,?,?,?)`,
    [empresaId, userId, data, v, responsavel, categoria, (descricao || "").trim(), local]
  );

  res.json({ ok: true });
});

app.get("/api/despesas", auth, async (req, res) => {
  const empresaId = req.user.empresa_id;
  const { ano, mes } = req.query;

  let where = "WHERE empresa_id = ?";
  const params = [empresaId];

  if (ano) {
    where += " AND substr(data,1,4) = ?";
    params.push(String(ano));
  }

  if (mes) {
    const mm = String(mes).padStart(2, "0");
    where += " AND substr(data,6,2) = ?";
    params.push(mm);
  }

  const rows = await all(
    `SELECT id, data, valor, responsavel, categoria, descricao, local
     FROM despesas
     ${where}
     ORDER BY data DESC, id DESC`,
    params
  );

  res.json({ despesas: rows });
});

app.put("/api/despesas/:id", auth, async (req, res) => {
  const empresaId = req.user.empresa_id;
  const id = Number(req.params.id);

  const { data, valor, responsavel, categoria, descricao, local } = req.body || {};

  if (!data || !responsavel || !categoria || !local) {
    return res.status(400).json({ error: "Campos obrigatórios faltando" });
  }

  const v = Number(valor);
  if (!Number.isFinite(v) || v <= 0) {
    return res.status(400).json({ error: "Valor inválido" });
  }

  await run(
    `UPDATE despesas
     SET data=?, valor=?, responsavel=?, categoria=?, descricao=?, local=?
     WHERE empresa_id=? AND id=?`,
    [data, v, responsavel, categoria, (descricao || "").trim(), local, empresaId, id]
  );

  res.json({ ok: true });
});

app.delete("/api/despesas/:id", auth, async (req, res) => {
  const empresaId = req.user.empresa_id;
  const id = Number(req.params.id);

  await run("DELETE FROM despesas WHERE empresa_id=? AND id=?", [empresaId, id]);
  res.json({ ok: true });
});

// ====== START ======
init().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`✅ Backend rodando em http://localhost:${port}`);
  });
});
