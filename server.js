const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

if (!fs.existsSync("users.json")) {
    fs.writeFileSync("users.json", "[]");
}

function getUsers() {
    return JSON.parse(fs.readFileSync("users.json"));
}

function saveUsers(users) {
    fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

function hashIp(ip) {
    return crypto.createHash("sha256").update(ip).digest("hex");
}

function getClientIp(req) {
    return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
}

function validInput(username, password) {
    if (username.length < 1 || username.length > 20) return false;
    if (password.length < 8 || password.length > 100) return false;
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return false;
    return true;
}

function isValidSecurityCode(code) {
    if (!code) return true;
    return /^SCULPT-[0-9]{7,12}$/.test(code);
}

app.get("/username-available", (req, res) => {
    const username = String(req.query.username || "").trim();

    if (username.length < 1 || username.length > 20 || !/^[a-zA-Z0-9_]+$/.test(username)) {
        return res.status(400).json({ error: "Username must be 1-20 letters, numbers, or _" });
    }

    const users = getUsers();
    const taken = users.some(u => u.username.toLowerCase() === username.toLowerCase());

    res.json({ available: !taken });
});

app.post("/signup", async (req, res) => {
    const { username, password, backupCode } = req.body;

    if (!validInput(username, password)) {
        return res.status(400).json({ error: "Username must be 1-20 chars and password must be 8-100 chars" });
    }

    if (!isValidSecurityCode(backupCode)) {
        return res.status(400).json({ error: "Backup code must look like SCULPT-9010101 (7-12 digits)." });
    }

    let users = getUsers();

    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(400).json({ error: "Username already exists" });
    }

    const hash = await bcrypt.hash(password, 12);
    const backupCodeHash = backupCode ? await bcrypt.hash(backupCode, 12) : null;
    const ipHash = hashIp(getClientIp(req));

    users.push({
        username,
        password: hash,
        backupCodeHash,
        trustedIpHashes: [ipHash]
    });
    saveUsers(users);

    req.session.user = username;
    res.json({ success: true });
});

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

    user.trustedIpHashes = user.trustedIpHashes || [];

    const ipHash = hashIp(getClientIp(req));
    const knownIp = user.trustedIpHashes.includes(ipHash);

    if (!knownIp) {
        req.session.pendingLogin = {
            username: user.username,
            passwordVerified: true,
            ipHash
        };
        return res.status(403).json({
            requiresVerification: true,
            requiresBackupCode: Boolean(user.backupCodeHash),
            error: "New login location detected. Please verify to continue."
        });
    }

    req.session.user = user.username;
    res.json({ success: true });
});

app.post("/login/verify", async (req, res) => {
    const { password, backupCode } = req.body;
    const pending = req.session.pendingLogin;

    if (!pending?.username) {
        return res.status(400).json({ error: "No verification request in progress." });
    }

    const users = getUsers();
    const user = users.find(u => u.username === pending.username);

    if (!user) {
        return res.status(401).json({ error: "Invalid login" });
    }

    const passwordOk = await bcrypt.compare(String(password || ""), user.password);
    if (!passwordOk) {
        return res.status(401).json({ error: "Password re-check failed." });
    }

    if (user.backupCodeHash) {
        const codeOk = await bcrypt.compare(String(backupCode || ""), user.backupCodeHash);
        if (!codeOk) {
            return res.status(401).json({ error: "Backup security code is incorrect." });
        }
    }

    user.trustedIpHashes = user.trustedIpHashes || [];
    if (!user.trustedIpHashes.includes(pending.ipHash)) {
        user.trustedIpHashes.push(pending.ipHash);
        saveUsers(users);
    }

    req.session.user = user.username;
    delete req.session.pendingLogin;

    res.json({ success: true });
});

app.get("/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ user: null });
    }
    res.json({ user: req.session.user });
});

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/login.html");
    }
    next();
}

app.get("/platform.html", requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "platform.html"));
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login.html");
    });
});

app.listen(PORT, () => {
    console.log("Running on http://localhost:" + PORT);
});
