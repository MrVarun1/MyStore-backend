const express = require("express");
const cors = require("cors");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const { env } = require("process");

const app = express();
app.use(express.json());
app.use(cors());

let db;

const initializeDbandServer = async () => {
  try {
    db = await open({
      filename: "./database.db",
      driver: sqlite3.Database,
    });
    console.log("Connected to Database");

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
  } catch (e) {
    console.log(`Error: ${e}`);
    process.exit(1);
  }
};

initializeDbandServer().then(() => {
  const router = require("./routes.js")(db);
  app.use("/api", router);
});
