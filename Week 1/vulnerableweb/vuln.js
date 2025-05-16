const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect("mongodb://localhost/vulnerableDB")
    .then(() => console.log("MongoDB connected!"))
    .catch(err => console.log("MongoDB connection error:", err));

// User schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});
const User = mongoose.model("User", userSchema);

// Home redirect
app.get("/", (req, res) => res.redirect("/login"));

// Signup routes
app.get("/signup", (req, res) => res.render("signup", { errorMessage: null }));

app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.render("signup", { errorMessage: "Username already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.redirect("/login");
    } catch (err) {
        console.log(err);
        res.render("signup", { errorMessage: "Error during signup" });
    }
});

// Login routes
app.get("/login", (req, res) => res.render("login", { errorMessage: null }));

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            res.redirect(`/profile?user=${encodeURIComponent(user.username)}`);
        } else {
            res.render("login", { errorMessage: "Invalid credentials" });
        }
    } catch (err) {
        console.log(err);
        res.render("login", { errorMessage: "Error during login" });
    }
});

// Profile (safe from XSS)
app.get("/profile", (req, res) => {
    const username = req.query.user;
    res.render("profile", { username });
});

app.listen(3000, () => console.log("App running at http://localhost:3000"));
