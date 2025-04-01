require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const db = require("./config/db"); // Database connection
const authRoutes = require("./routes/authRoutes");
const orderRoutes = require("./routes/orderRoutes"); // Ensure this file exists

const app = express(); // ✅ Initialize app before using it

// ✅ Middleware
app.use(cors({ origin: "http://localhost:5173", credentials: true })); // Adjust port as per your Vue.js frontend

app.use(bodyParser.json());

// ✅ Routes
app.use("/api/auth", authRoutes);  
app.use("/api", orderRoutes);  

// ✅ Test Database Connection
db.getConnection()
    .then((connection) => {
        console.log("✅ MySQL Connection Pool Initialized...");
        connection.release();
    })
    .catch((err) => console.error("❌ Error connecting to MySQL:", err.message));

// ✅ Register Routes Properly

// ✅ Register Route
app.post("/api/auth/register", async (req, res) => {
    const apiKey = req.headers["x-api-key"];
    
    if (!apiKey || apiKey !== "b12061391c2ee1c1369af80e74fe42d9c937d29c4fac81faab419708ac9f64d1") {
        return res.status(401).json({ message: "Unauthorized: Invalid API Key" });
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: "Please provide name, email, and password" });
    }

    try {
        const [existingUsers] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: "Email already registered. Use a different email." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const [result] = await db.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );

        console.log(`👤 User registered with ID: ${result.insertId}`);
        res.status(201).json({ message: "User registered successfully" });

    } catch (error) {
        console.error("🔥 Registration Error:", error);
        res.status(500).json({ message: "Failed to register user" });
    }
});


// ✅ Login Route
const jwt = require("jsonwebtoken");

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Please provide email and password" });
    }

    try {
        const [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

        if (users.length === 0) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const user = users[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // ✅ Generate JWT Token
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.status(200).json({ message: "Login successful", token });

    } catch (error) {
        console.error("🔥 Login Error:", error);
        res.status(500).json({ message: "Failed to login" });
    }
});


// ✅ Order Placement Route
app.post("/api/orders", async (req, res) => {
    try {
        console.log("📥 Received Order Data:", req.body);

        const { full_name, address, phone, total_amount, transaction_id } = req.body;

        if (!full_name || !address || !phone || !total_amount || !transaction_id) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const query = "INSERT INTO orders (full_name, address, phone, total_amount, transaction_id) VALUES (?, ?, ?, ?, ?)";
        const values = [full_name, address, phone, total_amount, transaction_id];

        // ✅ Run the query properly
        const [result] = await db.execute(query, values);

        console.log("✅ MySQL Insert Result:", result); // 🔍 Debugging SQL response

        // ✅ Check if order ID is generated
        if (!result.insertId) {
            console.error("❌ Order ID Not Generated!");
            return res.status(500).json({ message: "Error: Order ID not generated." });
        }

        res.status(201).json({ 
            message: "Order placed successfully!", 
            order_id: result.insertId
        });

    } catch (error) {
        console.error("🔥 Error placing order:", error);
        res.status(500).json({ message: "Error placing order", error });
    }
});



// ✅ Start Server AFTER defining routes
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
