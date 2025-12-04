// index.js

// 1. Core Module Imports
require("dotenv").config(); // Load environment variables from .env file
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10; // Standard for bcrypt hashing

// 2. Middleware Setup
app.use(express.json()); // Allows parsing of JSON request bodies

// Basic request logging for observability (can be replaced by a proper logger later)
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Basic health check endpoint for monitoring
app.get("/health", (_req, res) => {
  res
    .status(200)
    .json({
      status: "ok",
      service: "auth-service",
      time: new Date().toISOString(),
    });
});

// 3. Database Connection Pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Test the database connection
pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("❌ Database Connection Failed:", err.stack);
    // Exit application if database connection fails
    process.exit(1);
  } else {
    console.log("✅ Database connected successfully at:", res.rows[0].now);
  }
});

// =======================================================
// 4. Module 2.1: Authentication System (Staff Registration Route)
// =======================================================

// POST /api/auth/register
// Purpose: Bootstrap creation of initial staff (e.g., first Admin / Operators).
// Security note: In production this route should be restricted to Admins or disabled
// once initial staff accounts have been created.
app.post("/api/auth/register", async (req, res) => {
  const { username, password, role } = req.body;

  // Basic presence checks
  if (!username || !password || !role) {
    return res
      .status(400)
      .json({ message: "Missing username, password, or role." });
  }

  // Simple username validation (adjust to match SRS if needed)
  if (
    typeof username !== "string" ||
    username.length < 3 ||
    username.length > 50
  ) {
    return res
      .status(400)
      .json({ message: "Username must be between 3 and 50 characters." });
  }

  // Simple password policy (can be strengthened as requirements evolve)
  if (typeof password !== "string" || password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters long." });
  }

  // Enforce strict, known roles
  const allowedRoles = ["Admin", "Operator", "Viewer"];
  if (!allowedRoles.includes(role)) {
    return res
      .status(400)
      .json({ message: `Role must be one of: ${allowedRoles.join(", ")}.` });
  }

  try {
    // SECURITY STEP: Hash the password before storing it in the database.
    // Bcrypt automatically handles salting (adding unique randomness).
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // SQL Query to insert the new user into the 'users (staff)' table
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, role) 
       VALUES ($1, $2, $3) 
       RETURNING user_id, username, role, created_at`,
      [username, passwordHash, role]
    );

    // Respond with the newly created user (excluding the hash)
    return res.status(201).json({
      message: "Staff user registered successfully.",
      user: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      // PostgreSQL error code for unique violation (e.g., username already exists)
      return res.status(409).json({ message: "Username already exists." });
    }
    console.error("Registration error:", error);
    return res
      .status(500)
      .json({ message: "Internal server error during registration." });
  }
});

// =======================================================
// 4. Module 2.2: Authentication System (Staff Login Route)
// =======================================================
//
// POST /api/auth/login
// Purpose: Allow staff to authenticate with username and password and receive a JWT.
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Missing username or password." });
  }

  try {
    const userResult = await pool.query(
      `SELECT user_id, username, password_hash, role 
       FROM users 
       WHERE username = $1`,
      [username]
    );

    if (userResult.rows.length === 0) {
      // Do not reveal whether the username exists
      return res.status(401).json({ message: "Invalid username or password." });
    }

    const user = userResult.rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatches) {
      return res.status(401).json({ message: "Invalid username or password." });
    }

    // Issue JWT access token
    const token = jwt.sign(
      {
        user_id: user.user_id,
        username: user.username,
        role: user.role,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "30m",
      }
    );

    return res.status(200).json({
      message: "Login successful.",
      accessToken: token,
      user: {
        user_id: user.user_id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res
      .status(500)
      .json({ message: "Internal server error during login." });
  }
});

// =======================================================
// 4. Module 2.3: Authentication Middleware & Role-Based Authorization
// =======================================================
//
// authenticateToken: Verifies JWT from the Authorization header and attaches
// the decoded user payload to req.user.
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Expect "Bearer <token>"

  if (!token) {
    return res.status(401).json({ message: "Access token missing." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token." });
    }
    req.user = user;
    next();
  });
}

// authorizeRoles: Ensures the authenticated user has one of the allowed roles.
function authorizeRoles(...allowedRolesForRoute) {
  return (req, res, next) => {
    if (!req.user || !allowedRolesForRoute.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions." });
    }
    next();
  };
}

// Example protected route (can be removed or adapted once downstream modules are added)
// GET /api/auth/me - returns the currently authenticated user's profile details.
app.get("/api/auth/me", authenticateToken, (req, res) => {
  return res.status(200).json({ user: req.user });
});

// =======================================================
// 4. Module 2.4: Password Change Endpoint
// =======================================================
//
// POST /api/auth/change-password
// Purpose: Allow an authenticated staff member to change their own password.
app.post("/api/auth/change-password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res
      .status(400)
      .json({ message: "Missing currentPassword or newPassword." });
  }

  if (typeof newPassword !== "string" || newPassword.length < 8) {
    return res
      .status(400)
      .json({ message: "New password must be at least 8 characters long." });
  }

  try {
    const userResult = await pool.query(
      `SELECT user_id, password_hash 
       FROM users 
       WHERE user_id = $1`,
      [req.user.user_id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const user = userResult.rows[0];
    const matches = await bcrypt.compare(currentPassword, user.password_hash);

    if (!matches) {
      return res
        .status(401)
        .json({ message: "Current password is incorrect." });
    }

    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    await pool.query(
      `UPDATE users 
       SET password_hash = $1 
       WHERE user_id = $2`,
      [newPasswordHash, req.user.user_id]
    );

    return res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    console.error("Change password error:", error);
    return res
      .status(500)
      .json({ message: "Internal server error during password change." });
  }
});

// =======================================================
// 5. Server Startup
// =======================================================

app.listen(port, () => {
  console.log(
    `🚀 Authentication Service running on port ${port} in ${
      process.env.NODE_ENV || "development"
    } mode.`
  );
  console.log(`URL: http://localhost:${port}`);
});
