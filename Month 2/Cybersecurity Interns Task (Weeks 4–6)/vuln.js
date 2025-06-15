// ---------- Dependencies ----------
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const winston = require("winston");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();

// ---------- 1. Middleware Setup ----------

// View Engine & Parsing
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser()); // Required to read cookies

// Rate Limiting
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    message: "Too many requests from this IP, please try again later.",
});
//app.use(limiter);

// CORS Configuration
app.use(cors({
    origin: "http://localhost:5000",
    methods: ["GET", "POST"],
    credentials: true,
}));

// ---------- 2. API Key Middleware ----------
function apiKeyAuth(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    const expectedKey = process.env.API_KEY;

    console.log("Received API Key:", apiKey);
    console.log("Expected API Key:", expectedKey);

    if (!apiKey || apiKey !== expectedKey) {
        return res.status(403).json({ message: 'Forbidden: Invalid API Key' });
    }
    next();
}

// ---------- 3. Winston Logger ----------
const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: "security.log" }),
    ],
});
logger.info("Application started");

// ---------- 4. MongoDB Setup ----------
mongoose.connect("mongodb://localhost/vulnerableDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => logger.info("MongoDB connected!"))
.catch((err) => logger.error("MongoDB connection error:", err));

// ---------- 5. Mongoose Schema ----------
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});
const User = mongoose.model("User", userSchema);

// ---------- 6. Routes ----------

// Redirect root
app.get("/", (req, res) => res.redirect("/login"));

// SIGNUP
app.get("/signup", (req, res) => {
    res.render("signup", { errorMessage: null });
});

app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            logger.warn(`Signup attempt with existing username: ${username}`);
            return res.render("signup", { errorMessage: "Username already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        logger.info(`New user signed up: ${username}`);
        res.redirect("/login");
    } catch (err) {
        logger.error("Signup error:", err);
        res.render("signup", { errorMessage: "Error during signup" });
    }
});

// LOGIN
app.get("/login", (req, res) => {
    res.render("login", { errorMessage: null });
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            logger.info(`Successful login: ${username}`);
            res.cookie("username", username); // Save user in cookie
            res.redirect("/profile");
        } else {
            logger.warn(`Failed login attempt for username: ${username}`);
            res.render("login", { errorMessage: "Invalid credentials" });
        }
    } catch (err) {
        logger.error("Login error:", err);
        res.render("login", { errorMessage: "Error during login" });
    }
});

// PROFILE (API Key Protected)
app.get("/profile", apiKeyAuth, (req, res) => {
    const username = req.cookies?.username || "User";
    res.render("profile", { username });
});

// ---------- 7. Start Server ----------
const PORT = 5000;
app.listen(PORT, "0.0.0.0", () => {
    logger.info(`App running at http://0.0.0.0:${PORT}`);
});

