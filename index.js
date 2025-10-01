require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(helmet());
app.use(express.json());

// dev: only allow your react dev server; in production set to your domain
app.use(cors({ origin: process.env.CLIENT_ORIGIN || "http://localhost:5173" }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 60 }); // example
app.use(limiter);

// MySQL pool
const pool = mysql.createPool({
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: process.env.DB_NAME,
	waitForConnections: true,
	connectionLimit: 10,
});

// New Admin Registration Code
app.post("/api/admin-register", async (req, res) => {
	try {
		const {
			name,
			adminEmail,
			mobile,
			profilePicture,
			address,
			adminPassword,
		} = req.body;

		// 1️⃣ Generate a salt + hash
		const salt = await bcrypt.genSalt(10); // 10 rounds is common
		const hashedPassword = await bcrypt.hash(adminPassword, salt);

		const [result] = await pool.execute(
			"INSERT INTO admin (name, email, mobile, profile_picture, address, password) VALUES (?,?,?,?,?,?)",
			[name, adminEmail, mobile, profilePicture, address, hashedPassword]
		);
		return res.status(201).json({ success: true, id: result.insertId });
	} catch (err) {
		console.log(err);
		return res.status(500).json({ error: "Server Error" });
	}
});

// Display Admin Code
app.get("/api/registerd-admins", async (req, res) => {
	try {
		const [rows] = await pool.execute(
			"SELECT * FROM admin ORDER BY id DESC"
		);
		return res.json(rows);
	} catch (err) {
		console.error(err);
		return res.status(500).json({ error: "Server error" });
	}
});

// Admin Login Code
app.post("/api/login", async (req, res) => {
	const { adminEmail, adminPassword } = req.body;
	const [rows] = await pool.execute("SELECT * FROM admin WHERE email = ?", [
		adminEmail,
	]);

	if (rows.length === 0)
		return res.status(400).json({ message: "User Not Found!" });

	const isMatch = await bcrypt.compare(adminPassword, rows[0].password);
	if (!isMatch)
		return res.status(400).json({ message: "Invalid credentials" });

	const token = jwt.sign(
		{ id: rows[0].id, email: rows[0].email },
		process.env.JWT_SECRET,
		{ expiresIn: "1h" }
	);

	res.json({
		token,
		user: {
			id: rows[0].id,
			name: rows[0].name,
			email: rows[0].email,
			mobile: rows[0].mobile,
			profile_picture: rows[0].profile_picture,
			address: rows[0].address,
			password: rows[0].password,
			// চাইলে অন্য কলামগুলোও এখানে দিতে পারো
		},
	});
});

// Update Admin Information
app.put("/api/admin-profile/:id", async (req, res) => {
	try {
		const { id } = req.params;
		const { name, mobile, profilePicture, address } = req.body;
		const [result] = await pool.execute(
			"UPDATE admin SET name = ?, mobile =?, profile_picture = ?, address =? WHERE id = ?",
			[name, mobile, profilePicture, address, id]
		);

		if (result.affectedRows === 0) {
			return res
				.status(404)
				.json({ error: "Admin not found or no changes made" });
		}

		// 🔹 Fetch the updated user from DB
		const [rows] = await pool.execute(
			"SELECT id, name, email, mobile, profile_picture, address FROM admin WHERE id = ?",
			[id]
		);

		return res.json({
			success: true,
			message: "Profile updated successfully",
			user: rows[0], // ✅ updated user data
		});
	} catch (err) {
		console.error(err);
		return res.status(500).json({ error: "Server error" });
	}
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
