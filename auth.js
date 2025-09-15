const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Register and send verification email
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const user = new User({ email, passwordHash, verificationToken });
    await user.save();

    // Send verification email
    const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${email}`;

    await transporter.sendMail({
      from: `AI CV Maker <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verify your email for AI CV Maker",
      html: `<p>Thank you for registering.</p>
             <p>Please verify your email by clicking below:</p>
             <a href="${verifyUrl}">Verify Email</a>`,
    });

    res.json({ message: "Registration successful. Please check email to verify." });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

// Verify email endpoint
router.get("/verify-email", async (req, res) => {
  try {
    const { email, token } = req.query;
    if (!email || !token)
      return res.status(400).send("Invalid verification link");

    const user = await User.findOne({ email, verificationToken: token });
    if (!user) return res.status(400).send("Invalid or expired token");

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    res.send("Email verified! You can now log in.");
  } catch (err) {
    res.status(500).send("Verification failed");
  }
});

// Login route
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });
    if (!user.isVerified)
      return res.status(401).json({ error: "Please verify your email first" });

    const passMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passMatch) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

module.exports = router;
