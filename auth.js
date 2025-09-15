const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const User = require("./user");

const router = express.Router();

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
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

// Register -> email OTP
router.post("/register", async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    email = email.toLowerCase();
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "Email already registered" });

    const verificationOtp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins
    const passwordHash = await bcrypt.hash(password, 12);

    const user = new User({
      email,
      passwordHash,
      verificationOtp,
      verificationOtpExpires: otpExpires,
      isVerified: false,
    });
    await user.save();

    await transporter.sendMail({
      from: `AI CV Maker <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your Email Verification OTP",
      html: `<p>Your OTP for email verification is <b>${verificationOtp}</b>. It expires in 10 minutes.</p>`,
    });

    return res.json({ message: "Registration successful. Please verify OTP sent to email." });
  } catch (err) {
    return res.status(500).json({ error: "Registration failed" });
  }
});

// Verify OTP
router.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.verificationOtp || !user.verificationOtpExpires)
      return res.status(400).json({ error: "Invalid or expired OTP" });

    if (user.verificationOtp !== otp || user.verificationOtpExpires < Date.now())
      return res.status(400).json({ error: "Invalid or expired OTP" });

    user.isVerified = true;
    user.verificationOtp = undefined;
    user.verificationOtpExpires = undefined;
    await user.save();

    return res.json({ message: "Email verified successfully" });
  } catch (err) {
    return res.status(500).json({ error: "Verification failed" });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });
    if (!user.isVerified) return res.status(401).json({ error: "Please verify your email first" });
    if (user.isLocked) return res.status(403).json({ error: "Account locked. Try later." });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
        user.failedLoginAttempts = 0;
      }
      await user.save();
      return res.status(400).json({ error: "Invalid email or password" });
    }

    user.failedLoginAttempts = 0;
    user.lockUntil = undefined;

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();

    return res.json({ accessToken, refreshToken });
  } catch (err) {
    return res.status(500).json({ error: "Login failed" });
  }
});

// Refresh token
router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "Refresh token required" });

    const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const user = await User.findById(payload.id);
    if (!user || user.refreshToken !== refreshToken)
      return res.status(401).json({ error: "Invalid refresh token" });

    const newAccess = generateAccessToken(user);
    const newRefresh = generateRefreshToken(user);
    user.refreshToken = newRefresh;
    await user.save();

    return res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch (err) {
    return res.status(401).json({ error: "Could not refresh token" });
  }
});

// Logout
router.post("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.json({ message: "Logged out" });

    const payload = jwt.decode(refreshToken);
    if (payload?.id) {
      const user = await User.findById(payload.id);
      if (user && user.refreshToken === refreshToken) {
        user.refreshToken = undefined;
        await user.save();
      }
    }
    return res.json({ message: "Logged out" });
  } catch {
    return res.json({ message: "Logged out" });
  }
});

// Request password reset OTP
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.json({ message: "If account exists, OTP sent" });

    const otp = crypto.randomInt(100000, 999999).toString();
    user.resetPasswordOtp = otp;
    user.resetPasswordOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await transporter.sendMail({
      from: `AI CV Maker <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Your Password Reset OTP",
      html: `<p>Your OTP to reset password is <b>${otp}</b>. It expires in 10 minutes.</p>`,
    });

    return res.json({ message: "If account exists, OTP sent" });
  } catch (err) {
    return res.status(500).json({ error: "Could not process request" });
  }
});

// Reset password using OTP
router.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword)
      return res.status(400).json({ error: "Email, OTP, and newPassword required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (
      !user ||
      !user.resetPasswordOtp ||
      !user.resetPasswordOtpExpires ||
      user.resetPasswordOtp !== otp ||
      user.resetPasswordOtpExpires < Date.now()
    ) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    user.resetPasswordOtp = undefined;
    user.resetPasswordOtpExpires = undefined;
    await user.save();

    return res.json({ message: "Password reset successful" });
  } catch (err) {
    return res.status(500).json({ error: "Password reset failed" });
  }
});

module.exports = router;
