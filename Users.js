// Existing imports
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./database/dbConnect");
const express = require("express");

const router = express.Router();

// ===================== Authentication Middleware =====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Invalid token format." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretKey");
    req.user = decoded; // attach user info to request
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired token", error: error.message });
  }
};

// ===================== Register Route =====================
router.post("/register", async (req, res) => {
  const { name, email, username, password } = req.body;
  if (!name || !email || !username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);

    const query =
      "INSERT INTO Users(Full_Names, email, User_Name, Password) VALUES (?,?,?,?)";

    db.execute(query, [name, email, username, hashed], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Database error" });
      }

      const token = jwt.sign(
        { id: results.insertId, Full_Names: name, email, User_Name: username },
        process.env.JWT_SECRET || "secretKey",
        { expiresIn: "1h" }
      );

      res.status(201).json({ message: "User registered successfully", token });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// ===================== LOGIN ROUTE =====================
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  // Fetch user from MySQL
  const query = "SELECT * FROM Users WHERE User_Name = ?";
  db.execute(query, [username], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = results[0];

    // Compare hashed password
    const match = await bcrypt.compare(password, user.Password);
    if (!match) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Create JWT with user ID, role, and department
    const token = jwt.sign(
      {
        id: user.ID,          // assuming your primary key is ID
        username: user.User_Name,
        role: user.Role || "user",        // default to "user" if not in DB
        department: user.Department || "", // default empty if not in DB
      },
      process.env.JWT_SECRET || "secretKey",
      { expiresIn: "1h" }
    );

    res.status(200).json({ message: "Login successful", token });
  });
});

// ===================== Protected Route Example =====================
router.get("/profile", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Protected route accessed successfully", user: req.user });
});

module.exports = router;
