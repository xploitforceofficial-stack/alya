const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  guildId: { type: String, required: true },
  points: { type: Number, default: 0 },
  multiplier: { type: Number, default: 1 },
  lastViolation: { type: Date, default: null },
  suspicious: { type: Boolean, default: false },
  suspiciousReasons: [{ type: String }],
  joinDate: { type: Date, default: Date.now },
  lastMessages: [{
    content: String,
    timestamp: Number,
    messageId: String
  }],
  messageTimestamps: [{ type: Number }],
  offenseHistory: [{
    reason: String,
    timestamp: Date,
    severity: Number,
    points: Number
  }]
}, { timestamps: true });

// Compound index untuk memudahkan pencarian
userSchema.index({ userId: 1, guildId: 1 }, { unique: true });

module.exports = mongoose.model('User', userSchema);
