const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./database/dbConnect");
const express = require("express");

const router = express.Router();

/*JWT  MIDDLEWARE */

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  // Check if Authorization header exists

  if (!authHeader) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  // Format: Bearer TOKEN

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Invalid token format." });
  }

  try {

    // Verify token

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "secretKey"
    );

    // Attach user info to request

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(403).json({
      message: "Invalid or expired token",
      error: error.message,
    });
  }
};

/* REGISTER ROUTE */

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
        {
          id: results.insertId,
          Full_Names: name,
          email: email,
          User_Name: username,
        },
        process.env.JWT_SECRET || "secretKey",
        { expiresIn: "1h" }
      );

      res.status(201).json({
        message: "User registered successfully",
        token,
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
});

/* kurinda ROUTE EXAMPLE */

router.get("/profile", authenticateToken, (req, res) => {
  res.status(200).json({
    message: "Protected route accessed successfully",
    user: req.user,
  });
});

module.exports = router;
