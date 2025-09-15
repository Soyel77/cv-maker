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

const ACCESS_TOKEN_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY = "7d";

function generateAccessToken(user) {
  return jwt.sign({ id: user._id }, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

function generateRefreshToken(user) {
  return jwt.sign({ id: user._id }, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
}

// POST /api/auth/register
router.post("/register", async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    email = email.toLowerCase();

    let existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "Email already registered" });

    // Generate OTP
    const verificationOtp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

    const passwordHash = await bcrypt.hash(password, 12);

    const user = new User({
      email,
      passwordHash,
      verificationOtp,
      verificationOtpExpires: otpExpires,
    });
    await user.save();

    // Send OTP email
    await transporter.sendMail({
      from: `AI CV Maker <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your Email Verification OTP",
      html: `<p>Your OTP for email verification is: <b>${verificationOtp}</b>. It expires in 10 minutes.</p>`,
    });

    return res.json({ message: "Register successful. Check email for OTP." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// POST /api/auth/verify-email
router.post("/verify-email", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email" });
    if (user.isVerified) return res.json({ message: "Already verified" });

    if (user.verificationOtp !== otp || Date.now() > user.verificationOtpExpires) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    user.verificationOtp = null;
    user.verificationOtpExpires = null;
    await user.save();

    res.json({ message: "Email verified successfully" });
  } catch (err) {
    res.status(500).json({ error: "Verification failed" });
  }
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    email = email.toLowerCase();

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    if (user.isLocked) {
      return res.status(403).json({ error: "Account locked due to multiple failed login attempts. Try later or reset password." });
    }

    if (!user.isVerified) {
      return res.status(401).json({ error: "Please verify your email first." });
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatch) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // Lock for 30 mins
      }
      await user.save();
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // Reset failed attempts on successful login
    user.failedLoginAttempts = 0;
    user.lockUntil = null;

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// POST /api/auth/token - refresh access token
router.post("/token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: "Refresh token required" });

  try {
    const user = await User.findOne({ refreshToken });
    if (!user)
      return res.status(403).json({ error: "Invalid refresh token" });

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ error: "Invalid refresh token" });

      const accessToken = generateAccessToken(user);
      res.json({ accessToken });
    });
  } catch (err) {
    res.status(500).json({ error: "Could not refresh token" });
  }
});

// POST /api/auth/logout - logout and invalidate refresh token
router.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "Refresh token required" });

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) return res.status(400).json({ error: "Invalid refresh token" });

    user.refreshToken = null;
    await user.save();
    res.json({ message: "Successfully logged out" });
  } catch (err) {
    res.status(500).json({ error: "Logout failed" });
  }
});

// POST /api/auth/request-password-reset - send OTP to reset password
router.post("/request-password-reset", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ error: "No user with that email" });

    const otp = crypto.randomInt(100000, 999999).toString();
    user.resetPasswordOtp = otp;
    user.resetPasswordOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await transporter.sendMail({
      from: `AI CV Maker <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset OTP",
      html: `<p>Your OTP to reset password is: <b>${otp}</b>. It expires in 10 minutes.</p>`,
    });

    res.json({ message: "Password reset OTP sent to email" });
  } catch (err) {
    res.status(500).json({ error: "Failed to send reset OTP" });
  }
});

// POST /api/auth/reset-password - verify OTP and reset password
router.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword)
    return res.status(400).json({ error: "Email, OTP and new password required" });

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ error: "Invalid email" });
    if (user.resetPasswordOtp !== otp || Date.now() > user.resetPasswordOtpExpires) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    user.resetPasswordOtp = null;
    user.resetPasswordOtpExpires = null;
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    res.json({ message: "Password reset successfully" });
  } catch (err) {
    res.status(500).json({ error: "Password reset failed" });
  }
});

module.exports = router;
