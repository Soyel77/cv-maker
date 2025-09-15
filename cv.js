const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const CV = require("./CV");
const auth = require(".authMiddleware");

const router = express.Router();

const uploadsDir = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^\w.-]/g, "_");
    cb(null, `${Date.now()}_${safe}`);
  },
});
const upload = multer({ storage });

// Create or update CV
router.post("/", auth, upload.single("photo"), async (req, res) => {
  try {
    const { personalInfo, education, workExperience, certifications, skills, languages, interests } =
      req.body;

    const doc = {
      userId: req.user._id,
      photoFilename: req.file?.filename,
      personalInfo: personalInfo ? JSON.parse(personalInfo) : undefined,
      education: education ? JSON.parse(education) : undefined,
      workExperience: workExperience ? JSON.parse(workExperience) : undefined,
      certifications: certifications ? JSON.parse(certifications) : undefined,
      skills: skills ? JSON.parse(skills) : undefined,
      languages: languages ? JSON.parse(languages) : undefined,
      interests,
    };

    let cv = await CV.findOne({ userId: req.user._id });
    if (cv) {
      if (doc.photoFilename && cv.photoFilename && cv.photoFilename !== doc.photoFilename) {
        try {
          fs.unlinkSync(path.join(uploadsDir, cv.photoFilename));
        } catch {}
      }
      Object.assign(cv, doc);
      await cv.save();
    } else {
      cv = await CV.create(doc);
    }

    return res.json(cv);
  } catch (err) {
    return res.status(400).json({ error: "Invalid CV payload" });
  }
});

// Get my CV
router.get("/me", auth, async (req, res) => {
  const cv = await CV.findOne({ userId: req.user._id });
  return res.json(cv || null);
});

module.exports = router;
