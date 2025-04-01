exports.loginAdmin = async (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ? AND role = "admin"', [email], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ message: 'Admin not found' });

        const admin = results[0];
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: admin.id, role: admin.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
};
 
