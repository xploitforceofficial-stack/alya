const { Client, GatewayIntentBits, PermissionsBitField } = require("discord.js");
const mongoose = require("mongoose");
const config = require("./config");
const User = require("./models/User");

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.MessageContent
  ]
});

// ===== MongoDB Connect =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ===== Toxic Detection =====
function containsToxic(content) {
  const patterns = [
    /kontol|anjing|babi|ngentot|memek/i,
    /fuck|bitch|asshole|motherfucker|nigger/i,
    /puta|mierda|pendejo/i,
    /كسم|شرموطة/i,
    /(.)\1{5,}/i
  ];
  return patterns.some(p => p.test(content));
}

// ===== Scam Detection =====
function containsScam(content) {
  return /bit\.ly|tinyurl|discord.*nitro|http:\/\/\d+\.\d+\.\d+\.\d+/i.test(content);
}

// ===== Handle Violation =====
async function handleViolation(message, severity, reason) {
  let user = await User.findOne({
    userId: message.author.id,
    guildId: message.guild.id
  });

  if (!user) {
    user = new User({
      userId: message.author.id,
      guildId: message.guild.id
    });
  }

  const now = new Date();

  if ((now - user.lastViolation) < 48 * 60 * 60 * 1000) {
    user.multiplier += 0.5;
  } else {
    user.multiplier = 1;
  }

  if (user.suspicious) {
    severity *= 2;
  }

  user.points += severity * user.multiplier;
  user.lastViolation = now;
  user.offenseHistory.push(reason);

  await user.save();
  await punish(message.member, user.points);
}

// ===== Punishment =====
async function punish(member, points) {
  if (!member) return;

  if (points >= 50) {
    await member.ban({ reason: "Guardian Permanent Ban" });
  } else if (points >= 35) {
    await member.ban({ reason: "Guardian 1 Month Ban" });
  } else if (points >= 20) {
    await member.timeout(7 * 24 * 60 * 60 * 1000);
  } else if (points >= 10) {
    await member.timeout(24 * 60 * 60 * 1000);
  } else if (points >= 5) {
    await member.timeout(60 * 60 * 1000);
  }
}

// ===== Message Event =====
client.on("messageCreate", async message => {
  if (message.author.bot) return;

  let user = await User.findOne({
    userId: message.author.id,
    guildId: message.guild.id
  });

  if (!user) {
    user = new User({
      userId: message.author.id,
      guildId: message.guild.id
    });
  }

  const now = Date.now();

  // Spam
  user.messageTimestamps.push(now);
  user.messageTimestamps = user.messageTimestamps.filter(
    t => now - t < config.spamInterval
  );

  if (user.messageTimestamps.length >= config.spamLimit) {
    await message.delete().catch(()=>{});
    await handleViolation(message, 3, "Spam");
  }

  // Everyone abuse
  if ((message.content.includes("@everyone") || message.content.includes("@here")) &&
      !message.member.permissions.has(PermissionsBitField.Flags.MentionEveryone)) {
    await message.delete().catch(()=>{});
    await handleViolation(message, 7, "Everyone Abuse");
  }

  // Toxic
  if (containsToxic(message.content)) {
    await message.delete().catch(()=>{});
    await handleViolation(message, 5, "Toxic Language");
  }

  // Scam
  if (containsScam(message.content)) {
    await message.delete().catch(()=>{});
    await handleViolation(message, 8, "Scam Link");
  }

  // Attachment size
  if (message.attachments.size > 0) {
    message.attachments.forEach(att => {
      if (att.size > config.maxAttachmentMB * 1024 * 1024) {
        message.delete().catch(()=>{});
        handleViolation(message, 4, "Large Attachment");
      }
    });
  }

  await user.save();
});

// ===== Suspicious System =====
client.on("guildMemberAdd", async member => {
  const accountAge = Date.now() - member.user.createdTimestamp;
  const daysOld = accountAge / (1000 * 60 * 60 * 24);

  if (daysOld < config.suspiciousDays) {
    await User.findOneAndUpdate(
      { userId: member.id, guildId: member.guild.id },
      { suspicious: true },
      { upsert: true }
    );

    console.log(`${member.user.tag} flagged as suspicious`);
  }
});

client.login(process.env.TOKEN);
