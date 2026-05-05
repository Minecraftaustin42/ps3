const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🔒 stronger session config
app.use(session({
    name: "playsculpt.sid",
    secret: "super-secret-change-this",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax"
    }
}));

app.use(express.static(__dirname));

// ensure file
if (!fs.existsSync("users.json")) {
    fs.writeFileSync("users.json", "[]");
}

function getUsers() {
    return JSON.parse(fs.readFileSync("users.json"));
}

function saveUsers(users) {
    fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

// 🔒 simple validation
function validInput(username, password) {
    if (username.length < 3 || password.length < 5) return false;
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return false;
    return true;
}

// ✅ SIGNUP (auto login)
app.post("/signup", async (req, res) => {
    const { username, password } = req.body;

    if (!validInput(username, password)) {
        return res.status(400).json({ error: "Invalid username or password" });
    }

    let users = getUsers();

    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: "Username already exists" });
    }

    const hash = await bcrypt.hash(password, 12); // 🔒 stronger hashing

    users.push({ username, password: hash });
    saveUsers(users);

    // ✅ AUTO LOGIN
    req.session.user = username;

    res.json({ success: true });
});

// LOGIN
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    let users = getUsers();
    let user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ error: "Invalid login" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        return res.status(401).json({ error: "Invalid login" });
    }

    req.session.user = username;

    res.json({ success: true });
});

// 🔒 PROTECTED PAGE CHECK
app.get("/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ user: null });
    }
    res.json({ user: req.session.user });
});

// 🔒 middleware
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/login.html");
    }
    next();
}

// 🔒 protect platform page
app.get("/platform.html", requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "platform.html"));
});

// logout
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login.html");
    });
});

app.listen(PORT, () => {
    console.log("Running on http://localhost:" + PORT);
});