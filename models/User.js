const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  userId: String,
  guildId: String,
  points: { type: Number, default: 0 },
  lastViolation: { type: Date, default: Date.now },
  offenseHistory: [{ type: String }],
  multiplier: { type: Number, default: 1 },
  suspicious: { type: Boolean, default: false },
  messageTimestamps: [{ type: Number }]
});

module.exports = mongoose.model("User", userSchema);
