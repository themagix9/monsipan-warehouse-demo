import express from "express";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const { Pool } = pkg;
const app = express();
app.use(express.json());

/* =========================
   CONFIG
========================= */

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  host: process.env.DB_HOST || "localhost",
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.sendStatus(401);

  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}

// ===============================
// ADMIN: Produkt-Stammdaten
// ===============================
app.get("/admin/products", auth, async (req, res) => {
  // 🔒 Nur Admins
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const result = await pool.query(`
  SELECT
    p.id,
    p.name,
    p.material_type,
    p.default_package,
    p.active,
    COALESCE(SUM(s.quantity), 0) AS total_quantity
  FROM products p
  LEFT JOIN stock s ON s.product_id = p.id
  GROUP BY p.id
  ORDER BY total_quantity DESC
`);

  res.json(result.rows);
});

// ===============================
// ADMIN: Produkt aktualisieren
// ===============================
app.put("/admin/products/:id", auth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { id } = req.params;
  const { name, default_package, active } = req.body;

  try {
    await pool.query(
      `
      UPDATE products
      SET
        name = $1,
        default_package = $2,
        active = $3
      WHERE id = $4
      `,
      [name, default_package, active, id]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("Admin product update failed:", err);
    res.status(500).json({ error: "update failed" });
  }
});

// ===============================
// ADMIN: User anlegen
// ===============================
app.post("/admin/users", auth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { username, password, role, active } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      `
      INSERT INTO users (username, password_hash, role, active)
      VALUES ($1, $2, $3, $4)
      `,
      [username, hash, role, active ?? true]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("Create user failed:", e);
    res.status(500).json({ error: "create failed" });
  }
});

// ===============================
// ADMIN: Userliste
// ===============================
app.get("/admin/users", auth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const result = await pool.query(`
    SELECT
      id,
      username,
      first_name,
      last_name,
      role,
      active,
      created_at
    FROM users
    ORDER BY created_at ASC
  `);

  res.json(result.rows);

  // ===============================
  // ADMIN: User bearbeiten
  // ===============================
  app.put("/admin/users/:id", auth, async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    const check = await pool.query(
      "SELECT role FROM users WHERE id = $1",
      [req.params.id]
    );

    if (check.rows[0]?.role === "admin") {
      return res.status(403).json({ error: "Admin user cannot be modified" });
    }

    const { first_name, last_name, role, active } = req.body;

    await pool.query(
      `
      UPDATE users
      SET
        first_name = $1,
        last_name = $2,
        role = $3,
        active = $4
      WHERE id = $5
      `,
      [first_name, last_name, role, active, req.params.id]
    );

    res.json({ ok: true });
  });

/* =========================
   DB INIT
========================= */

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        barcode TEXT UNIQUE NOT NULL,
        name TEXT
      );

      CREATE TABLE IF NOT EXISTS stock (
        product_id INT PRIMARY KEY REFERENCES products(id),
        quantity INT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS movements (
        id SERIAL PRIMARY KEY,
        product_id INT REFERENCES products(id),
        change INT NOT NULL,
        type TEXT NOT NULL,
        user_id INT REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log("DB ready & tables ensured");
  } finally {
    client.release();
  }
}

async function ensureAdmin() {
  const res = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    ["admin"]
  );

  if (res.rowCount === 0) {
    const hash = await bcrypt.hash("admin123", 10);
    await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)",
      ["admin", hash, "admin"]
    );
    console.log("Default admin created (admin / admin123)");
  }
}

/* =========================
   STARTUP
========================= */

await initDb();
await ensureAdmin();

/* =========================
   ROUTES
========================= */

app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", db: "connected" });
  } catch {
    res.status(500).json({ status: "error", db: "down" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1 AND active = true",
    [username]
  );

  if (result.rowCount === 0) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);

  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({ token });
});

app.post("/scan", auth, async (req, res) => {
  const { barcode, type } = req.body;
  if (!barcode || !["IN", "OUT"].includes(type)) {
    return res.status(400).json({ error: "Invalid scan" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    let product = await client.query(
      "SELECT * FROM products WHERE barcode = $1",
      [barcode]
    );

    if (product.rowCount === 0) {
      product = await client.query(
        "INSERT INTO products (barcode) VALUES ($1) RETURNING *",
        [barcode]
      );
    }

    const productId = product.rows[0].id;
    const delta = type === "IN" ? 1 : -1;

    await client.query(
      `
      INSERT INTO stock (product_id, quantity)
      VALUES ($1, GREATEST($2,0))
      ON CONFLICT (product_id)
      DO UPDATE SET quantity = GREATEST(stock.quantity + $2,0)
      `,
      [productId, delta]
    );

    await client.query(
      `
      INSERT INTO movements (product_id, change, type, user_id)
      VALUES ($1,$2,$3,$4)
      `,
      [productId, delta, type, req.user.id]
    );

    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "scan failed" });
  } finally {
    client.release();
  }
});

/* =========================
   SERVER
========================= */

app.listen(PORT, () => {
  console.log(`Backend listening on ${PORT}`);
});

/* =========================
   Lagerbestand-Auswahl
========================= */

app.get("/stock", auth, async (req, res) => {
  const result = await pool.query(`
    SELECT
      p.id,
      p.barcode,
      p.name,
      p.color,
      p.material_type,
      p.package,
      p.shelf,
      COALESCE(s.quantity, 0) AS quantity
    FROM products p
    LEFT JOIN stock s ON s.product_id = p.id
    ORDER BY p.shelf, p.color, p.material_type
  `);

  res.json(result.rows);
});
