const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");

const DB_PATH = "./database.sqlite";
const db = new sqlite3.Database(DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

async function ensureColumn(table, columnDefSql) {
  try {
    await run(`ALTER TABLE ${table} ADD COLUMN ${columnDefSql}`);
  } catch (e) {
    // coluna já existe, ignora
  }
}

async function init() {
  // ===== EMPRESAS =====
  await run(`
    CREATE TABLE IF NOT EXISTS empresas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // ===== USERS =====
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // adiciona colunas novas (se já existir tabela antiga)
  await ensureColumn("users", "nome TEXT");
  await ensureColumn("users", "role TEXT DEFAULT 'user'");
  await ensureColumn("users", "empresa_id INTEGER");

  // ===== DESPESAS =====
  await run(`
    CREATE TABLE IF NOT EXISTS despesas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      data TEXT NOT NULL,            -- YYYY-MM-DD
      valor REAL NOT NULL,
      responsavel TEXT NOT NULL,
      categoria TEXT NOT NULL,
      descricao TEXT,
      local TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // adiciona empresa_id em despesas
  await ensureColumn("despesas", "empresa_id INTEGER");

  // ===== CADASTROS =====
  await run(`
    CREATE TABLE IF NOT EXISTS cad_responsaveis (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      nome TEXT NOT NULL,
      UNIQUE(user_id, nome)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS cad_categorias (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      nome TEXT NOT NULL,
      UNIQUE(user_id, nome)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS cad_locais (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      nome TEXT NOT NULL,
      UNIQUE(user_id, nome)
    )
  `);

  // adiciona empresa_id nas tabelas auxiliares
  await ensureColumn("cad_responsaveis", "empresa_id INTEGER");
  await ensureColumn("cad_categorias", "empresa_id INTEGER");
  await ensureColumn("cad_locais", "empresa_id INTEGER");

  // ===== ADMIN (cria se não existir) =====
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPass = process.env.ADMIN_PASSWORD;

  if (!adminEmail || !adminPass) {
    console.log("⚠️ ADMIN_EMAIL e ADMIN_PASSWORD não definidos no .env");
    return;
  }

  // cria/pega uma empresa padrão
  let empresa = await get("SELECT id FROM empresas WHERE nome = ?", ["ATHOS"]);
  if (!empresa) {
    await run("INSERT INTO empresas(nome) VALUES(?)", ["ATHOS"]);
    empresa = await get("SELECT id FROM empresas WHERE nome = ?", ["ATHOS"]);
  }
  const empresaId = empresa.id;

  // cria admin se não existir
  const exists = await get("SELECT id FROM users WHERE email = ?", [adminEmail]);
  if (!exists) {
    const hash = await bcrypt.hash(adminPass, 10);
    await run(
      "INSERT INTO users(email, password_hash, role, nome, empresa_id) VALUES(?,?,?,?,?)",
      [adminEmail, hash, "admin", "Administrador", empresaId]
    );
    console.log("✅ Usuário admin criado:", adminEmail);
  }

  // ✅ GARANTIA REAL: admin SEMPRE admin, mesmo se antes estava "user"
  await run("UPDATE users SET role = 'admin' WHERE email = ?", [adminEmail]);

  // garante empresa_id e nome se estiverem faltando
  await run(
    "UPDATE users SET empresa_id = COALESCE(empresa_id, ?) WHERE email = ?",
    [empresaId, adminEmail]
  );

  await run(
    "UPDATE users SET nome = COALESCE(nome, 'Administrador') WHERE email = ?",
    [adminEmail]
  );

  // ===== MIGRAÇÃO: vincular dados antigos à empresa do admin =====
  const adminRow = await get("SELECT id, empresa_id FROM users WHERE email = ?", [adminEmail]);

  if (adminRow?.empresa_id) {
    // despesas antigas: coloca empresa_id onde estiver null
    await run("UPDATE despesas SET empresa_id = ? WHERE empresa_id IS NULL", [adminRow.empresa_id]);

    // cadastros antigos: coloca empresa_id onde estiver null
    await run("UPDATE cad_responsaveis SET empresa_id = ? WHERE empresa_id IS NULL", [adminRow.empresa_id]);
    await run("UPDATE cad_categorias SET empresa_id = ? WHERE empresa_id IS NULL", [adminRow.empresa_id]);
    await run("UPDATE cad_locais SET empresa_id = ? WHERE empresa_id IS NULL", [adminRow.empresa_id]);
  }

  console.log("✅ Banco inicializado com empresa_id (dados compartilhados por empresa).");
}

module.exports = { db, run, get, all, init };
