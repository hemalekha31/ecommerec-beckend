const express = require("express");
const db = require("../config/db");  // Import database connection

const router = express.Router();

// ✅ Order Placement Route
router.post("/orders", async (req, res) => {
    console.log("📥 Received Order Data:", req.body);

    const { full_name, address, phone, total_amount, transaction_id } = req.body;

    if (!full_name || !address || !phone || !total_amount || !transaction_id) {
        return res.status(400).json({ message: "All fields are required." });
    }

    try {
        const [result] = await db.execute(
            "INSERT INTO orders (full_name, address, phone, total_amount, transaction_id) VALUES (?, ?, ?, ?, ?)",
            [full_name, address, phone, total_amount, transaction_id]
        );

        if (result.affectedRows === 0) {
            return res.status(500).json({ message: "Failed to insert order." });
        }

        console.log("✅ Order Inserted:", result.insertId);
        res.status(201).json({ message: "Order placed successfully", orderId: result.insertId });

    } catch (error) {
        console.error("🔥 Error inserting order:", error);
        res.status(500).json({ message: "Database error", error: error.message });
    }
});

// ✅ GET: Fetch All Orders (For Customers)
router.get("/orders", async (req, res) => {
    try {
        const [orders] = await db.query("SELECT order_id, full_name, total_amount, created_at FROM orders ORDER BY created_at DESC");
        res.status(200).json(orders);
    } catch (error) {
        console.error("🔥 Database error:", error.message);
        res.status(500).json({ message: "Database error", error: error.message });
    }
});

// ✅ GET: Admin Orders (Admin Panel) with Pagination
router.get("/admin/orders", async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    try {
        const sql = "SELECT order_id, full_name, address, phone, total_amount, transaction_id, created_at FROM orders ORDER BY order_id DESC LIMIT ? OFFSET ?";
        const [orders] = await db.execute(sql, [parseInt(limit), parseInt(offset)]);
        res.status(200).json(orders);
    } catch (error) {
        console.error("🔥 Error fetching orders:", error.message);
        res.status(500).json({ message: "Database error", error: error.message });
    }
});

// ✅ Health Check Route (Removed duplicate `/`)
router.get("/health", (req, res) => {
    res.send("Orders API is working!");
});

module.exports = router;
