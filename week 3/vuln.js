const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const winston = require("winston");

const app = express();

// Set up view engine
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Winston logger setup
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

// MongoDB Connection
mongoose
    .connect("mongodb://localhost/vulnerableDB", { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => logger.info("MongoDB connected!"))
    .catch((err) => logger.error("MongoDB connection error:", err));

// Mongoose User Schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});
const User = mongoose.model("User", userSchema);

// Home Route
app.get("/", (req, res) => res.redirect("/login"));

// Signup Routes
app.get("/signup", (req, res) => res.render("signup", { errorMessage: null }));

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

// Login Routes
app.get("/login", (req, res) => res.render("login", { errorMessage: null }));

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            logger.info(`Successful login: ${username}`);
            res.redirect(`/profile?user=${encodeURIComponent(user.username)}`);
        } else {
            logger.warn(`Failed login attempt for username: ${username}`);
            res.render("login", { errorMessage: "Invalid credentials" });
        }
    } catch (err) {
        logger.error("Login error:", err);
        res.render("login", { errorMessage: "Error during login" });
    }
});

// Profile Route (XSS mitigated)
app.get("/profile", (req, res) => {
    const username = req.query.user;
    res.render("profile", { username });
});

// Start Server
app.listen(3000, () => {
    logger.info("App running at http://localhost:3000");
});
