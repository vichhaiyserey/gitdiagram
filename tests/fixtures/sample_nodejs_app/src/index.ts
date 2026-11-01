import express from "express";

const app = express();
app.use(express.json());

app.get("/api/users", (req, res) => {
  res.json([]);
});

app.post("/api/checkout", (req, res) => {
  res.json({ success: true });
});

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});
