// index.js

// 1. Core Module Imports
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10; // Standard for bcrypt hashing

// 2. Middleware Setup
app.use(express.json()); // Allows parsing of JSON request bodies

// 3. Database Connection Pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Test the database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database Connection Failed:', err.stack);
    // Exit application if database connection fails
    process.exit(1);
  } else {
    console.log('✅ Database connected successfully at:', res.rows[0].now);
  }
});

// =======================================================
// 4. Module 2.1: Authentication System (Staff Registration Route)
// =======================================================

// POST /api/auth/register
// NOTE: In a real system, only an existing Admin should be able to create new users. 
// This is a bootstrap route for initial setup.
app.post('/api/auth/register', async (req, res) => {
  const { username, password, role } = req.body;
  
  if (!username || !password || !role) {
    return res.status(400).send({ message: 'Missing username, password, or role.' });
  }

  try {
    // SECURITY STEP: Hash the password before storing it in the database
    // Bcrypt automatically handles salting (adding unique randomness).
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Default 'Operator' if role is invalid, or use the provided role.
    const userRole = ['Admin', 'Operator', 'Viewer'].includes(role) ? role : 'Operator'; 

    // SQL Query to insert the new user into the 'users (staff)' table
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, role) 
       VALUES ($1, $2, $3) 
       RETURNING user_id, username, role, created_at`,
      [username, passwordHash, userRole]
    );

    // Respond with the newly created user (excluding the hash)
    res.status(201).send({ 
        message: 'Staff user registered successfully.', 
        user: result.rows[0] 
    });

  } catch (error) {
    if (error.code === '23505') { // PostgreSQL error code for unique violation (e.g., username already exists)
      return res.status(409).send({ message: 'Username already exists.' });
    }
    console.error('Registration error:', error);
    res.status(500).send({ message: 'Internal server error during registration.' });
  }
});

// =======================================================
// 5. Server Startup
// =======================================================

app.listen(port, () => {
  console.log(`🚀 Authentication Service running on port ${port} in ${process.env.NODE_ENV || 'development'} mode.`);
  console.log(`URL: http://localhost:${port}`);
});