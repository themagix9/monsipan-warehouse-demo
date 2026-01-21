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
  if (!header) return res.status(401).json({ error: "UNAUTHORIZED" });

  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "UNAUTHORIZED" });
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

  const {
  username,
  password,
  first_name,
  last_name,
  role,
  active
} = req.body;


  if (!username || !password || !role) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      `
      INSERT INTO users (
  username,
  password_hash,
  first_name,
  last_name,
  role,
  active
)
VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [
  username,  // $1 → username
  hash,      // $2 → password_hash ✅
  first_name,// $3 → first_name
  last_name, // $4 → last_name
  role,      // $5 → role
  active     // $6 → active
]
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
});

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

app.post("/admin/users/:id/reset-password", auth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const defaultPassword = "Monsipan123!";
  const hash = await bcrypt.hash(defaultPassword, 10);

  await pool.query(
    `
    UPDATE users
    SET
      password_hash = $1,
      must_change_password = true
    WHERE id = $2
    `,
    [hash, req.params.id]
  );

  res.json({ ok: true, password: defaultPassword });
});

// ============================
// USER: Passwort ändern
// ============================
app.post("/me/change-password", auth, async (req, res) => {
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: "Password too short" });
  }

  const hash = await bcrypt.hash(newPassword, 10);

  await pool.query(
    `
    UPDATE users
    SET
      password_hash = $1,
      must_change_password = false
    WHERE id = $2
    `,
    [hash, req.user.id]
  );

  res.json({ ok: true });
});


// ============================
// USER: Eigene Daten abrufen
// ============================
app.get("/me", auth, async (req, res) => {
  const result = await pool.query(
    `
    SELECT
      id,
      username,
      first_name,
      last_name,
      role,
      must_change_password
    FROM users
    WHERE id = $1
    `,
    [req.user.id]
  );

  res.json(result.rows[0]);
});

// ============================
// USER: PW-Reset Pflicht
// ============================
app.post("/me/change-password", auth, async (req, res) => {
  const { password } = req.body;

  if (!password || password.length < 8) {
    return res.status(400).json({ error: "Password too short" });
  }

  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    `
    UPDATE users
    SET password_hash = $1,
        must_change_password = false
    WHERE id = $2
    `,
    [hash, req.user.id]
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
        product_id INT REFERENCES products(id),
        location TEXT NOT NULL DEFAULT 'Anlieferung',
        quantity INT NOT NULL DEFAULT 0,
        PRIMARY KEY (product_id, location)
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

  res.json({
  token,
  must_change_password: user.must_change_password
});
});

app.post("/scan", auth, async (req, res) => {
  const { barcode, type, location, qty } = req.body;

  if (!barcode || !["IN", "OUT"].includes(type)) {
    return res.status(400).json({ error: "Invalid scan" });
  }

  // 🔐 Pflichtprüfung für Einbuchungen
if (type === "IN" && (!location || !location.trim())) {
  return res.status(400).json({ error: "LOCATION_REQUIRED" });
}

const loc = location.trim();
  const amount = Number.isFinite(Number(qty)) && Number(qty) > 0 ? Number(qty) : 1;
  const delta = type === "IN" ? amount : -amount;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Produkt holen (nur aktive)
    const productRes = await client.query(
      `
      SELECT id, active
      FROM products
      WHERE barcode = $1
      LIMIT 1
      `,
      [barcode]
    );

    if (productRes.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "PRODUCT_NOT_FOUND" });
    }

    const product = productRes.rows[0];
    if (!(product.active === true || product.active === 1)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "PRODUCT_INACTIVE" });
    }

    // Bestand upserten pro (product_id, location)
    const stockRes = await client.query(
      `
      INSERT INTO stock (product_id, location, quantity)
      VALUES ($1, $2, GREATEST($3, 0))
      ON CONFLICT (product_id, location)
      DO UPDATE SET quantity = GREATEST(stock.quantity + $3, 0)
      RETURNING quantity
      `,
      [product.id, loc, delta]
    );

    // optional: movement log (ohne location bei dir aktuell)
    await client.query(
      `
      INSERT INTO movements (product_id, change, type, user_id)
      VALUES ($1,$2,$3,$4)
      `,
      [product.id, delta, type, req.user.id]
    );

    await client.query("COMMIT");
    res.json({ ok: true, new_quantity: stockRes.rows[0].quantity });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("scan failed:", e);
    res.status(500).json({ error: "scan failed" });
  } finally {
    client.release();
  }
});


/* =========================
   Lagerbestand-Auswahl
========================= */

app.get("/stock", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        p.id,
        p.barcode,
        p.name,
        p.material_type,
        p.color,

        COALESCE(
          NULLIF(regexp_replace(p.package, '[^0-9]', '', 'g'), '')::INT,
          p.default_package,
          0
        ) AS package,

        s.location,
        s.quantity

      FROM stock s
      JOIN products p ON p.id = s.product_id
      WHERE p.active = 1
        AND s.quantity <> 0
      ORDER BY s.location, p.name;
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("STOCK LOAD ERROR:", err.message);
    res.status(500).json({ error: "STOCK_LOAD_FAILED" });
  }
});


app.get("/products/by-barcode/:barcode", auth, async (req, res) => {
  const { barcode } = req.params;

  try {
    const result = await pool.query(
      `
      SELECT
        id,
        barcode,
        name,
        color,
        material_type
      FROM products
      WHERE barcode = $1
        AND active IS TRUE
      LIMIT 1
      `,
      [barcode]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "PRODUCT_NOT_FOUND" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("GET /products/by-barcode failed:", err);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});


/* =========================
   SERVER
========================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend listening on 0.0.0.0:${PORT}`);
});
