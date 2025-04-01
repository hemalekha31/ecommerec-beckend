const jwt = require("jsonwebtoken");
require("dotenv").config(); // Load environment variables

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(403).json({ message: "❌ Access denied, no token provided." });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => { // ✅ Corrected key name
        if (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(401).json({ message: "❌ Token expired" });
            }
            return res.status(401).json({ message: "❌ Invalid token" });
        }

        req.user = decoded; // Attach user details to request
        next();
    });
};

module.exports = authMiddleware;
