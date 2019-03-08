const express = require("express");
const argon2 = require("argon2");
const { writeFile, readFile } = require("fs").promises;
const { createHash } = require("crypto");
const path = require("path");

const app = express();

app.use(express.json());

app.get("/ping", (req, res) => {
  res.send("pong");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const filename = deriveFilename(username);

  try {
    const hash = await argon2.hash(password);
    await writeFile(filename, hash, "utf8");
    res.status(201).send("ok");
  } catch (err) {
    console.error(err);
    res.status(500).send("error");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const filename = deriveFilename(username);

  try {
    const hash = await readFile(filename, "utf8");
    if (await argon2.verify(hash, password)) {
      res.status(200).send("ok");
    } else {
      res.status(400).send("not ok");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("error");
  }
});

app.listen(process.env.PORT || 5000, () => {
  console.log("started...");
});

function deriveFilename(username) {
  const sha256 = createHash("sha256");
  sha256.update(username, "utf8");

  return path.join(__dirname, "db", sha256.digest().toString("hex"));
}
