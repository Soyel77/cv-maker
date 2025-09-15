const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  passwordHash: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  verificationOtp: { type: String },              // OTP code for email verification
  verificationOtpExpires: { type: Date },
  resetPasswordOtp: { type: String },             // OTP code for password reset
  resetPasswordOtpExpires: { type: Date },
  refreshToken: { type: String },                  // Latest refresh token (for one session)
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },                       // Account lock time
});

userSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

module.exports = mongoose.model("User", userSchema);
