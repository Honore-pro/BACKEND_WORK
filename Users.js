// Existing imports
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./database/dbConnect");
const express = require("express");

const router = express.Router();

// === Authentication Middleware ===
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
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired token", error: error.message });
  }
};

// === Admin Authorization Middleware ===
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ 
      message: "Access denied. Admin privileges required." 
    });
  }
  next();
};

// === Register Route ===
router.post("/register", async (req, res) => {
  const { name, email, username, password } = req.body;
  if (!name || !email || !username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);

    const query =
      "INSERT INTO users(Full_Names, email, User_Name, Password, Role) VALUES (?,?,?,?,?)";

    db.execute(query, [name, email, username, hashed, "user"], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Database error", error: err.message });
      }

      const token = jwt.sign(
        { id: results.insertId, Full_Names: name, email, User_Name: username, role: "user" },
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

// === Login Route ===
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  const query = "SELECT * FROM users WHERE User_Name = ?";
  db.execute(query, [username], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = results[0];

    const match = await bcrypt.compare(password, user.Password);
    if (!match) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign(
      {
        id: user.ID,
        username: user.User_Name,
        role: user.Role || "user",       
        department: user.Department || "", 
      },
      process.env.JWT_SECRET || "secretKey",
      { expiresIn: "1h" }
    );

    res.status(200).json({ 
      message: "Login successful", 
      token,
      user: {
        id: user.ID,
        username: user.User_Name,
        role: user.Role || "user"
      }
    });
  });
});

// === User Profile Route (Own profile only) ===
router.get("/profile/:id", authenticateToken, (req, res) => {
  const requestedId = parseInt(req.params.id); 
  const tokenUserId = req.user.id;             

  if (requestedId !== tokenUserId) {
    return res.status(403).json({
      message: "Access denied. You can only access your own profile.",
    });
  }

  const query = "SELECT ID, Full_Names, email, User_Name, Role, Department FROM users WHERE ID = ?";
  db.execute(query, [requestedId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "Profile accessed successfully",
      profile: results[0],
    });
  });
});

// ========== ADMIN ROUTES ==========

// === Admin: Get All Users ===
router.get("/admin/users", authenticateToken, authorizeAdmin, (req, res) => {
  const query = "SELECT ID, Full_Names, email, User_Name, Role, Department FROM users";
  
  db.execute(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    res.status(200).json({
      message: "Users retrieved successfully",
      count: results.length,
      users: results,
    });
  });
});

// === Admin: Get Specific User Profile ===
router.get("/admin/users/:id", authenticateToken, authorizeAdmin, (req, res) => {
  const userId = parseInt(req.params.id);

  const query = "SELECT ID, Full_Names, email, User_Name, Role, Department FROM users WHERE ID = ?";
  
  db.execute(query, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "User profile retrieved successfully",
      user: results[0],
    });
  });
});

// === Admin: Update User Profile ===
router.put("/admin/users/:id", authenticateToken, authorizeAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  const { name, email, username, role, department } = req.body;

  if (!name && !email && !username && !role && !department) {
    return res.status(400).json({ message: "At least one field is required to update" });
  }

  // Build dynamic query
  let updateFields = [];
  let values = [];

  if (name) {
    updateFields.push("Full_Names = ?");
    values.push(name);
  }
  if (email) {
    updateFields.push("email = ?");
    values.push(email);
  }
  if (username) {
    updateFields.push("User_Name = ?");
    values.push(username);
  }
  if (role) {
    updateFields.push("Role = ?");
    values.push(role);
  }
  if (department) {
    updateFields.push("Department = ?");
    values.push(department);
  }

  values.push(userId);

  const query = `UPDATE users SET ${updateFields.join(", ")} WHERE ID = ?`;

  db.execute(query, values, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "User profile updated successfully",
    });
  });
});

// === Admin: Delete User ===
router.delete("/admin/users/:id", authenticateToken, authorizeAdmin, (req, res) => {
  const userId = parseInt(req.params.id);

  // Prevent admin from deleting themselves
  if (userId === req.user.id) {
    return res.status(400).json({ message: "You cannot delete your own account" });
  }

  const query = "DELETE FROM users WHERE ID = ?";

  db.execute(query, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Database error" });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "User deleted successfully",
    });
  });
});

// === Admin: Reset User Password ===
router.put("/admin/users/:id/reset-password", authenticateToken, authorizeAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { newPassword } = req.body;

  if (!newPassword) {
    return res.status(400).json({ message: "New password is required" });
  }

  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    const query = "UPDATE users SET Password = ? WHERE ID = ?";

    db.execute(query, [hashed, userId], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Database error" });
      }

      if (results.affectedRows === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      res.status(200).json({
        message: "Password reset successfully",
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

module.exports = router;