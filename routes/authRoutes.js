const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
require("dotenv").config();

const router = express.Router();
const authMiddleware = require("../middleware/authMiddleware");

// ✅ Ensure Environment Variables Exist at Startup
if (!process.env.JWT_SECRET || !process.env.API_KEY) {
    console.error("🔥 Missing ENV Variables (JWT_SECRET, API_KEY). Check .env file!");
    process.exit(1);
}

// ✅ API Key Middleware (Optional for Login)
router.post("/wishlist", authMiddleware, async (req, res) => {
    const { product_id } = req.body;
    const user_id = req.user.userId;  // ✅ Get user ID from JWT token

    try {
        await db.execute("INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)", [user_id, product_id]);
        res.status(201).json({ message: "✅ Item added to wishlist!" });
    } catch (error) {
        console.error("🔥 Wishlist Error:", error);
        res.status(500).json({ message: "❌ Error adding to wishlist" });
    }
});

// 🔵 REGISTER ROUTE (User Signup)
router.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: "⚠️ Please provide name, email, and password." });
    }

    try {
        // 🔹 Check if user already exists
        const [existingUsers] = await db.execute("SELECT id FROM users WHERE email = ?", [email]);

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: "❌ Email already registered. Use a different email." });
        }

        // ✅ Secure Password Hashing (12 Rounds)
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // 🔹 Insert New User
        const [result] = await db.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );

        console.log(`✅ User Registered - ID: ${result.insertId}`);
        res.status(201).json({ message: "✅ User registered successfully", userId: result.insertId });

    } catch (error) {
        console.error("🔥 Registration Error:", error.code || error.message);
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "❌ Email already registered." });
        }
        res.status(500).json({ message: "❌ Internal Server Error", error: error.message });
    }
});

// 🔵 LOGIN ROUTE (JWT Authentication)
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "⚠️ Please provide email and password." });
    }

    try {
        const [users] = await db.execute("SELECT id, name, email, password FROM users WHERE email = ?", [email]);

        if (users.length === 0) {
            return res.status(401).json({ message: "❌ Invalid email or password" });
        }

        const user = users[0];

        // 🔹 Compare Hashed Password
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ message: "❌ Invalid email or password" });
        }

        // 🔹 Generate Secure JWT Token
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || "2h" }
        );

        console.log(`✅ Login Successful - User: ${user.email}`);
        return res.status(200).json({
            message: "✅ Login successful",
            token,
            user: {
                userId: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error("🔥 Login Error:", error);
        return res.status(500).json({ message: "❌ Internal Server Error", error: error.message });
    }
});

module.exports = router;
