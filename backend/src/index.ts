import express from "express";

const app = express();
const port = Number(process.env.PORT ?? 3001);

app.get("/api/health", (_request, response) => {
  response.json({
    status: "ok",
    message: "SENTRA backend is running",
  });
});

app.listen(port, () => {
  console.log(`SENTRA backend listening on port ${port}`);
});
