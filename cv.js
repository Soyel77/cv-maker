const mongoose = require("mongoose");

const cvSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  photoFilename: { type: String },
  personalInfo: {
    fullName: String,
    contactNumber: String,
    whatsappNumber: String,
    email: String,
    linkedin: String,
    portfolio: String,
    summary: String,
  },
  education: [String],
  workExperience: [String],
  certifications: [String],
  skills: [String],
  languages: [
    {
      name: String,
      proficiency: String,
    },
  ],
  interests: String,
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("CV", cvSchema);
