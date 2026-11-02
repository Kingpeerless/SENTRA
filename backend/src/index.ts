import { createApp } from "./api/app.js";
import { SentraDatabase } from "./database/database.js";

const port = Number(process.env.PORT ?? 3001);
const database = new SentraDatabase();
const app = createApp(database);

app.listen(port, () => {
  console.log(`SENTRA backend listening on port ${port}`);
});
