const jwt = require("jsonwebtoken");
const { get } = require("./db");

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;

    if (!token) return res.status(401).json({ error: "Token ausente" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // ✅ pega dados atuais do usuário no banco (role/empresa_id/nome)
    const user = await get(
      "SELECT id, email, nome, role, empresa_id FROM users WHERE id = ?",
      [payload.id]
    );

    if (!user) return res.status(401).json({ error: "Usuário inválido" });

    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Acesso permitido apenas para admin" });
  }
  next();
}

module.exports = { auth, requireAdmin };
