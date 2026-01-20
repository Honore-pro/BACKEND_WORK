const express = require('express');
const db = require("./database/dbConnect");
const app = express();
const PORT = 3000;
const UsersRouter = require("./Users");


app.use(express.json());

// Loggings
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});



app.get("/api/packages", (req, res) => {
  const sql = "SELECT * FROM packages";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});



app.get("/api/packages/:id", (req, res) => {
  const id = req.params.id;
  const sql = "SELECT * FROM packages WHERE P_id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0)
      return res.status(404).json({ message: "Package not found" });

    res.json(results[0]);
  });
});



app.post("/api/packages", (req, res) => {
  const data = req.body;

  const sql = `
    INSERT INTO packages 
    (P_name, quality, destination, sender, Weight, ship_date, delivery_date, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [
      data.P_name,
      data.quality,
      data.destination,
      data.sender,
      data.Weight,
      data.ship_date,
      data.delivery_date,
      data.status
    ],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      res.status(201).json({
        message: "Package created successfully",
        id: result.insertId,
        ...data
      });
    }
  );
});



app.put("/api/packages/:id", (req, res) => {
  const id = req.params.id;
  const data = req.body;

  const sql = `
    UPDATE packages SET
      P_name = ?, quality = ?, destination = ?, sender = ?, Weight = ?,
      ship_date = ?, delivery_date = ?, status = ?
    WHERE P_id = ?
  `;

  db.query(
    sql,
    [
      data.P_name,
      data.quality,
      data.destination,
      data.sender,
      data.Weight,
      data.ship_date,
      data.delivery_date,
      data.status,
      id
    ],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      if (result.affectedRows === 0)
        return res.status(404).json({ message: "Package not found" });

      res.json({ message: "Package updated successfully" });
    }
  );
});




app.delete("/api/packages/:id", (req, res) => {
  const id = req.params.id;
  const sql = "DELETE FROM packages WHERE P_id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    if (result.affectedRows === 0)
      return res.status(404).json({ message: "Package not found" });

    res.json({ message: "Package deleted successfully" });
  });
});


// guchecking error
app.use((err, req, res, next) => {
  console.log(err);
  res.status(500).json({ message: "Something went wrong!" });
});



app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


app.use('/users', UsersRouter);

