require("dotenv").config();
const mysql = require("mysql2/promise"); // ✅ Use mysql2 with promise support

const db = mysql.createPool({
    host: process.env.DB_HOST || "127.0.0.1",
    user: process.env.DB_USER || "hem2429",
    password: process.env.DB_PASSWORD || "hema24",
    database: process.env.DB_DATABASE || "backendsql",
    connectionLimit: 10,
});

// ✅ Test MySQL Connection
db.getConnection()
    .then((connection) => {
        console.log("✅ MySQL Connection Pool Initialized...");
        connection.release();
    })
    .catch((err) => console.error("❌ Error connecting to MySQL:", err.message));

module.exports = db;
