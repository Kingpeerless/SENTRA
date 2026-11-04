import { createApp } from "./api/app.js";
import { SentraDatabase } from "./database/database.js";

const port = Number(process.env.PORT ?? 3001);
const database = new SentraDatabase();
const app = createApp(database);

app.listen(port, "127.0.0.1", () => {
  console.log(`SENTRA backend listening on http://127.0.0.1:${port}`);
});
