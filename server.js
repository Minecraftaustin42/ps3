const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const PORT = 3000;
const CODE_TTL_MS = 15 * 60 * 1000;

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ name: "playsculpt.sid", secret: "super-secret-change-this", resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: "lax" } }));
app.use(express.static(__dirname));

if (!fs.existsSync("users.json")) fs.writeFileSync("users.json", "[]");
const getUsers = () => JSON.parse(fs.readFileSync("users.json"));
const saveUsers = (users) => fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
const hashIp = (ip) => crypto.createHash("sha256").update(ip).digest("hex");
app.set("trust proxy", true);
const getClientIp = (req) => {
    const fromForwarded = req.headers["x-forwarded-for"]?.split(",")[0]?.trim();
    const fromReal = req.headers["x-real-ip"] || req.headers["cf-connecting-ip"];
    return fromForwarded || fromReal || req.ip || req.socket.remoteAddress || "unknown";
};
const randomSixDigit = () => String(Math.floor(100000 + Math.random() * 900000));
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validInput = (username, password) => username.length >= 1 && username.length <= 20 && password.length >= 8 && password.length <= 100 && /^[a-zA-Z0-9_]+$/.test(username);

function requireAuth(req, res, next) {
    if (!req.session.user) return res.redirect('/login.html');
    next();
}

app.get("/username-available", (req, res) => {
    const username = String(req.query.username || "").trim();
    if (username.length < 1 || username.length > 20 || !/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: "Username must be 1-20 letters, numbers, or _" });
    res.json({ available: !getUsers().some(u => u.username.toLowerCase() === username.toLowerCase()) });
});

app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    if (!validInput(username, password)) return res.status(400).json({ error: "Username must be 1-20 chars and password must be 8-100 chars" });
    const users = getUsers();
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: "Username already exists" });
    users.push({ username, password: await bcrypt.hash(password, 12), trustedIpHashes: [hashIp(getClientIp(req))], email: null, emailVerified: false, emailCodeHash: null, emailCodeExpiresAt: null, pendingNewEmail: null });
    saveUsers(users);
    req.session.user = username;
    res.json({ success: true });
});

app.get('/settings/me', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const user = getUsers().find(u => u.username === req.session.user);
    if (!user) return res.status(404).json({ error: 'User missing' });
    res.json({ email: user.email, emailVerified: Boolean(user.emailVerified) });
});

app.post('/settings/email', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!isValidEmail(email)) return res.status(400).json({ error: "Enter a valid email." });
    const users = getUsers();
    const user = users.find(u => u.username === req.session.user);
    if (!user) return res.status(404).json({ error: "User missing" });

    const code = randomSixDigit();
    user.email = email; user.emailVerified = false;
    user.emailCodeHash = await bcrypt.hash(code, 10);
    user.emailCodeExpiresAt = Date.now() + CODE_TTL_MS;
    saveUsers(users);

    try { await transporter.sendMail({ from: process.env.GMAIL_USER, to: email, subject: "Playsculpt email confirmation code", text: `Your Playsculpt code is ${code}. It expires in 15 minutes.` }); }
    catch { return res.status(500).json({ error: "Could not send email. Check Gmail env vars." }); }

    res.json({ message: "Confirmation code sent to your email." });
});

app.post('/settings/email/confirm', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
    const code = String(req.body.code || "").trim();
    const users = getUsers();
    const user = users.find(u => u.username === req.session.user);
    if (!user || !user.emailCodeHash || !user.emailCodeExpiresAt) return res.status(400).json({ error: "No confirmation in progress." });
    if (Date.now() > user.emailCodeExpiresAt) return res.status(400).json({ error: "Code expired. Request a new one." });
    if (!(await bcrypt.compare(code, user.emailCodeHash))) return res.status(400).json({ error: "Invalid code." });
    user.emailVerified = true; user.emailCodeHash = null; user.emailCodeExpiresAt = null;
    saveUsers(users);
    res.json({ message: "Email confirmed successfully." });
});

app.post('/settings/email/change', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
    const { newEmail, currentPassword } = req.body;
    const email = String(newEmail || '').trim().toLowerCase();
    if (!isValidEmail(email)) return res.status(400).json({ error: "Enter a valid new email." });

    const users = getUsers();
    const user = users.find(u => u.username === req.session.user);
    if (!user) return res.status(404).json({ error: "User missing" });

    if (!(await bcrypt.compare(String(currentPassword || ''), user.password))) return res.status(401).json({ error: "Current password is incorrect." });

    const trusted = (user.trustedIpHashes || []).includes(hashIp(getClientIp(req)));
    if (!trusted) return res.status(403).json({ error: "We cannot verify this request. Please contact Playsculpt support for help to change your email." });

    const code = randomSixDigit();
    user.pendingNewEmail = { email, codeHash: await bcrypt.hash(code, 10), expiresAt: Date.now() + CODE_TTL_MS };
    saveUsers(users);

    try { await transporter.sendMail({ from: process.env.GMAIL_USER, to: email, subject: "Playsculpt change-email verification code", text: `Your Playsculpt code is ${code}. It expires in 15 minutes.` }); }
    catch { return res.status(500).json({ error: "Could not send email. Check Gmail env vars." }); }

    res.json({ message: "Verification code sent to new email." });
});

app.post('/settings/email/change/confirm', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
    const code = String(req.body.code || '').trim();
    const users = getUsers();
    const user = users.find(u => u.username === req.session.user);
    const pending = user?.pendingNewEmail;
    if (!user || !pending) return res.status(400).json({ error: "No email change request in progress." });
    if (Date.now() > pending.expiresAt) return res.status(400).json({ error: "Code expired. Start change again." });
    if (!(await bcrypt.compare(code, pending.codeHash))) return res.status(400).json({ error: "Invalid code." });
    user.email = pending.email; user.emailVerified = true; user.pendingNewEmail = null;
    saveUsers(users);
    res.json({ message: "Email changed and verified." });
});

app.post('/login', async (req, res) => { /* unchanged */
    const { username, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Invalid login" });
    user.trustedIpHashes = user.trustedIpHashes || [];
    const ipHash = hashIp(getClientIp(req));
    if (!user.trustedIpHashes.includes(ipHash)) {
        const pending = { username: user.username, ipHash, expiresAt: Date.now() + CODE_TTL_MS, requiresEmailCode: Boolean(user.email && user.emailVerified) };
        if (pending.requiresEmailCode) {
            const code = randomSixDigit();
            pending.emailCodeHash = await bcrypt.hash(code, 10);
            try { await transporter.sendMail({ from: process.env.GMAIL_USER, to: user.email, subject: "Playsculpt suspicious login code", text: `Your Playsculpt login code is ${code}. It expires in 15 minutes.` }); }
            catch { pending.requiresEmailCode = false; }
        }
        req.session.pendingLogin = pending;
        return res.status(403).json({ requiresVerification: true, requiresEmailCode: pending.requiresEmailCode, error: "New login location detected. Please verify to continue." });
    }
    req.session.user = user.username;
    res.json({ success: true });
});

app.post('/login/verify', async (req, res) => {
    const pending = req.session.pendingLogin;
    const { password, emailCode } = req.body;
    if (!pending?.username) return res.status(400).json({ error: "No verification request in progress." });
    if (Date.now() > pending.expiresAt) return res.status(400).json({ error: "Verification session expired. Login again." });
    const users = getUsers();
    const user = users.find(u => u.username === pending.username);
    if (!user || !(await bcrypt.compare(String(password || ""), user.password))) return res.status(401).json({ error: "Password re-check failed." });
    if (pending.requiresEmailCode && (!emailCode || !(await bcrypt.compare(String(emailCode), pending.emailCodeHash || "")))) return res.status(401).json({ error: "Invalid email verification code." });
    user.trustedIpHashes = user.trustedIpHashes || [];
    if (!user.trustedIpHashes.includes(pending.ipHash)) { user.trustedIpHashes.push(pending.ipHash); saveUsers(users); }
    req.session.user = user.username;
    delete req.session.pendingLogin;
    res.json({ success: true });
});

app.get('/me', (req, res) => { if (!req.session.user) return res.status(401).json({ user: null }); res.json({ user: req.session.user }); });
app.get('/platform.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'platform.html')));
app.get('/settings.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'settings.html')));
app.get('/studio.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'studio.html')));
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login.html')));

app.listen(PORT, () => console.log('Running on http://localhost:' + PORT));
