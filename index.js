import express from "express";

const app = express();
app.use(express.json());

app.get("/health", (_req, res) => {
  res.send("OK");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend listening on ${PORT}`);
});
