const { Client, GatewayIntentBits, PermissionsBitField, EmbedBuilder, ChannelType } = require("discord.js");
const mongoose = require("mongoose");
const config = require("./config");
const User = require("./models/User");

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMessageReactions,
    GatewayIntentBits.GuildModeration,
    GatewayIntentBits.GuildInvites,
    GatewayIntentBits.GuildVoiceStates
  ]
});

// ===== MongoDB Connect =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ===== Log Channel Configuration =====
const LOG_CHANNEL_ID = '1359068998544789645'; // Channel ID untuk log

// ===== Enhanced Toxic Detection with ML-like scoring =====
function analyzeContent(content) {
  const patterns = {
    toxic: {
      indonesian: /kontol|anjing|babi|ngentot|memek|goblok|bodoh|tolol|ngentod|jancok|asu|bangsat|bajingan|kampret|dongo|belegug/i,
      english: /fuck|bitch|asshole|motherfucker|nigger|shit|damn|piss off|cunt|dickhead|bastard|wanker|twat|prick/i,
      spanish: /puta|mierda|pendejo|cabron|verga|cojones|chingar|carajo|concha/i,
      arabic: /كسم|شرموطة|متناك|ابن الكلب|كس امك|نيق|شرموط/i,
      repeated: /(.)\1{8,}/i,
      zalgo: /[̗̙̖̬̥̰̜̼͔͕̼̘̮͚̻̲̝̺̦̱̞̠̤̩̙̘̮̲̫̬̦͓]/
    },
    harassment: {
      personal: /kamu (jelek|bodoh|goblok)|you (ugly|stupid|dumb|idiot)/i,
      threatening: /(saya akan|gua bakal|i will|im gonna) (bunuh|kill|hajar|beat|destroy) (kamu|you)/i,
      doxxing: /(alamat|address|rumah|house) (saya|gua|my) (di|at)|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    },
    scam: {
      links: /bit\.ly|tinyurl|discord\.gift|discord\.com\/gifts|free nitro|steamcommunity\.com\/offer|free robux|free v-bucks|airdrop|giveaway.*(nitro|robux)|hacked account|account generator/i,
      ipGrabber: /http:\/\/\d+\.\d+\.\d+\.\d+:\d+|\d+\.\d+\.\d+\.\d+\/grab|iplogger|grabify/i,
      crypto: /(free|bonus) (bitcoin|ethereum|crypto)|double your (bitcoin|money)/i,
      nsfw: /underage|teen.*(porn|sex)|loli|shota/i
    },
    advertising: {
      server: /discord\.gg\/[a-zA-Z0-9]+|discord\.com\/invite\/[a-zA-Z0-9]+/i,
      social: /(youtube|instagram|tiktok|twitter)\.com\/[a-zA-Z0-9_]+/i,
      selling: /(jual|selling|beli|buying) (jasa|service|akun|account|boost|nitro)|price \$\d+/i
    }
  };

  let score = 0;
  let reasons = [];

  // Check each category
  for (const [category, subPatterns] of Object.entries(patterns)) {
    for (const [type, pattern] of Object.entries(subPatterns)) {
      if (pattern.test(content)) {
        score += config.severity[category]?.[type] || 2;
        reasons.push(`${category}:${type}`);
      }
    }
  }

  // Check for excessive caps (possible yelling/aggression)
  const capsCount = (content.match(/[A-Z]/g) || []).length;
  if (content.length > 10 && capsCount / content.length > 0.7) {
    score += 3;
    reasons.push("excessive_caps");
  }

  // Check for mass mentions
  const mentionCount = (content.match(/<@!?&\d+>/g) || []).length;
  if (mentionCount > 3) {
    score += mentionCount * 2;
    reasons.push("mass_mentions");
  }

  return { score, reasons };
}

// ===== Spam Detection with advanced heuristics =====
class SpamDetector {
  constructor() {
    this.messageCache = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  checkSpam(message) {
    const userId = message.author.id;
    const now = Date.now();
    
    if (!this.messageCache.has(userId)) {
      this.messageCache.set(userId, []);
    }

    const userMessages = this.messageCache.get(userId);
    userMessages.push({
      content: message.content,
      timestamp: now,
      channelId: message.channelId
    });

    // Remove old messages
    const recentMessages = userMessages.filter(m => now - m.timestamp < config.spamInterval);
    this.messageCache.set(userId, recentMessages);

    // Check for spam patterns
    let score = 0;
    let reasons = [];

    // Rapid messages
    if (recentMessages.length >= config.spamLimit) {
      score += 3;
      reasons.push("rapid_messages");
    }

    // Same content repetition
    const contentCount = recentMessages.filter(m => m.content === message.content).length;
    if (contentCount >= 3) {
      score += contentCount;
      reasons.push("message_repetition");
    }

    // Cross-channel spam
    const uniqueChannels = new Set(recentMessages.map(m => m.channelId)).size;
    if (uniqueChannels >= 3 && recentMessages.length >= 5) {
      score += 4;
      reasons.push("cross_channel_spam");
    }

    // Mass mentions in spam context
    const mentionCount = (message.content.match(/<@!?&\d+>/g) || []).length;
    if (mentionCount > 2 && recentMessages.length >= 2) {
      score += mentionCount * 2;
      reasons.push("spam_with_mentions");
    }

    return { score, reasons };
  }

  cleanup() {
    const now = Date.now();
    for (const [userId, messages] of this.messageCache) {
      const recent = messages.filter(m => now - m.timestamp < config.spamInterval);
      if (recent.length === 0) {
        this.messageCache.delete(userId);
      } else {
        this.messageCache.set(userId, recent);
      }
    }
  }
}

const spamDetector = new SpamDetector();

// ===== Handle Violation with enhanced logging =====
async function handleViolation(message, severity, reason, additionalInfo = {}) {
  if (!message.member) return;

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

  // Time-based multiplier decay
  if ((now - user.lastViolation) < 48 * 60 * 60 * 1000) {
    user.multiplier += 0.5;
  } else if ((now - user.lastViolation) > 7 * 24 * 60 * 60 * 1000) {
    user.multiplier = Math.max(1, user.multiplier - 0.5);
  }

  // Suspicious user multiplier
  if (user.suspicious) {
    user.multiplier *= 1.5;
  }

  // Calculate points
  const points = severity * user.multiplier;
  user.points += points;
  user.lastViolation = now;
  user.offenseHistory.push({
    reason: reason,
    timestamp: now,
    severity: severity,
    points: points
  });

  await user.save();

  // Log the violation
  await logAction(message.guild, {
    type: 'WARNING',
    user: message.author,
    moderator: client.user,
    reason: reason,
    details: additionalInfo,
    points: points,
    totalPoints: user.points
  });

  // Apply punishment
  await punish(message.member, user.points, reason);
}

// ===== Enhanced Punishment System =====
async function punish(member, points, lastReason) {
  if (!member) return;

  let action = null;
  let duration = null;

  if (points >= 100) {
    await member.ban({ reason: `Guardian: Permanent Ban - ${lastReason}` });
    action = 'PERMANENT_BAN';
  } else if (points >= 75) {
    await member.ban({ reason: `Guardian: 6 Month Ban - ${lastReason}` });
    action = 'SIX_MONTH_BAN';
  } else if (points >= 50) {
    await member.ban({ reason: `Guardian: 1 Month Ban - ${lastReason}` });
    action = 'ONE_MONTH_BAN';
  } else if (points >= 35) {
    await member.ban({ reason: `Guardian: 1 Week Ban - ${lastReason}` });
    action = 'ONE_WEEK_BAN';
  } else if (points >= 25) {
    await member.timeout(14 * 24 * 60 * 60 * 1000, `Guardian: 2 Week Timeout - ${lastReason}`);
    action = 'TWO_WEEK_TIMEOUT';
    duration = '14 days';
  } else if (points >= 20) {
    await member.timeout(7 * 24 * 60 * 60 * 1000, `Guardian: 1 Week Timeout - ${lastReason}`);
    action = 'ONE_WEEK_TIMEOUT';
    duration = '7 days';
  } else if (points >= 15) {
    await member.timeout(3 * 24 * 60 * 60 * 1000, `Guardian: 3 Day Timeout - ${lastReason}`);
    action = 'THREE_DAY_TIMEOUT';
    duration = '3 days';
  } else if (points >= 10) {
    await member.timeout(24 * 60 * 60 * 1000, `Guardian: 24 Hour Timeout - ${lastReason}`);
    action = 'DAY_TIMEOUT';
    duration = '24 hours';
  } else if (points >= 5) {
    await member.timeout(60 * 60 * 1000, `Guardian: 1 Hour Timeout - ${lastReason}`);
    action = 'HOUR_TIMEOUT';
    duration = '1 hour';
  }

  if (action) {
    await logAction(member.guild, {
      type: action,
      user: member.user,
      moderator: client.user,
      reason: lastReason,
      duration: duration,
      points: points
    });
  }
}

// ===== Logging Function =====
async function logAction(guild, data) {
  try {
    const channel = await guild.channels.fetch(LOG_CHANNEL_ID).catch(() => null);
    if (!channel) return;

    const embed = new EmbedBuilder()
      .setTitle(`🛡️ Guardian Action: ${data.type}`)
      .setColor(getColorForAction(data.type))
      .setTimestamp()
      .setFooter({ text: 'Guardian Security System' });

    // Add user info
    embed.addFields({ 
      name: '👤 User', 
      value: `${data.user.tag} (<@${data.user.id}>)`, 
      inline: true 
    });

    // Add moderator info
    if (data.moderator) {
      embed.addFields({ 
        name: '🛡️ Moderator', 
        value: `${data.moderator.tag}`, 
        inline: true 
      });
    }

    // Add reason
    embed.addFields({ 
      name: '📝 Reason', 
      value: data.reason || 'No reason provided', 
      inline: false 
    });

    // Add points if available
    if (data.points) {
      embed.addFields({ 
        name: '⚡ Points', 
        value: `${data.points.toFixed(1)}`, 
        inline: true 
      });
    }

    // Add total points if available
    if (data.totalPoints) {
      embed.addFields({ 
        name: '📊 Total Points', 
        value: `${data.totalPoints.toFixed(1)}`, 
        inline: true 
      });
    }

    // Add duration if available
    if (data.duration) {
      embed.addFields({ 
        name: '⏱️ Duration', 
        value: data.duration, 
        inline: true 
      });
    }

    // Add additional details
    if (data.details && Object.keys(data.details).length > 0) {
      const detailsStr = Object.entries(data.details)
        .map(([k, v]) => `**${k}:** ${v}`)
        .join('\n');
      embed.addFields({ 
        name: '📋 Additional Details', 
        value: detailsStr, 
        inline: false 
      });
    }

    await channel.send({ embeds: [embed] });
  } catch (error) {
    console.error('Error logging action:', error);
  }
}

function getColorForAction(type) {
  const colors = {
    'WARNING': 0xFFA500,
    'HOUR_TIMEOUT': 0xFFA500,
    'DAY_TIMEOUT': 0xFF4500,
    'THREE_DAY_TIMEOUT': 0xFF4500,
    'ONE_WEEK_TIMEOUT': 0xFF0000,
    'TWO_WEEK_TIMEOUT': 0xFF0000,
    'ONE_WEEK_BAN': 0x8B0000,
    'ONE_MONTH_BAN': 0x8B0000,
    'SIX_MONTH_BAN': 0x8B0000,
    'PERMANENT_BAN': 0x4B0000,
    'MESSAGE_DELETED': 0x808080,
    'KICK': 0xFF0000
  };
  return colors[type] || 0x000000;
}

// ===== Message Event with enhanced security =====
client.on("messageCreate", async message => {
  if (message.author.bot) return;
  if (!message.guild) return;

  // Check for dangerous permissions in invites
  if (message.content.includes("discord.gg/") || message.content.includes("discord.com/invite/")) {
    try {
      const inviteCode = message.content.match(/(?:discord\.gg\/|discord\.com\/invite\/)([a-zA-Z0-9]+)/)[1];
      const invite = await client.fetchInvite(inviteCode).catch(() => null);
      
      if (invite && invite.guild) {
        // Check if it's a competitor server or suspicious server
        if (invite.guild.name.toLowerCase().includes("hack") || 
            invite.guild.name.toLowerCase().includes("cheat") ||
            invite.guild.name.toLowerCase().includes("free nitro") ||
            invite.memberCount > 10000) { // Large server invites might be spam
          
          await message.delete().catch(() => {});
          await handleViolation(message, 6, "Suspicious Server Invite", {
            serverName: invite.guild.name,
            memberCount: invite.memberCount
          });
        }
      }
    } catch (error) {
      // Invalid invite, delete it
      await message.delete().catch(() => {});
      await handleViolation(message, 4, "Invalid/Unknown Invite");
    }
  }

  // Get user data
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

  // ===== Advanced Spam Detection =====
  const spamResult = spamDetector.checkSpam(message);
  if (spamResult.score > 0) {
    await message.delete().catch(() => {});
    await handleViolation(message, spamResult.score, "Spam Detection", {
      patterns: spamResult.reasons
    });
    return;
  }

  // ===== Content Analysis =====
  const contentAnalysis = analyzeContent(message.content);
  if (contentAnalysis.score > 0) {
    await message.delete().catch(() => {});
    await handleViolation(message, contentAnalysis.score, "Content Violation", {
      patterns: contentAnalysis.reasons
    });
    return;
  }

  // ===== Attachment Analysis =====
  if (message.attachments.size > 0) {
    for (const attachment of message.attachments.values()) {
      // Check file size
      if (attachment.size > config.maxAttachmentMB * 1024 * 1024) {
        await message.delete().catch(() => {});
        await handleViolation(message, 4, "Large Attachment", {
          fileName: attachment.name,
          sizeMB: (attachment.size / (1024 * 1024)).toFixed(2)
        });
        return;
      }

      // Check file type
      const dangerousExtensions = ['.exe', '.msi', '.bat', '.cmd', '.sh', '.jar', '.vbs', '.ps1'];
      const fileExt = attachment.name.substring(attachment.name.lastIndexOf('.')).toLowerCase();
      if (dangerousExtensions.includes(fileExt)) {
        await message.delete().catch(() => {});
        await handleViolation(message, 8, "Dangerous File Type", {
          fileName: attachment.name,
          fileType: fileExt
        });
        return;
      }
    }
  }

  // ===== Message Update Tracking =====
  if (!user.lastMessages) user.lastMessages = [];
  user.lastMessages.push({
    content: message.content,
    timestamp: now,
    messageId: message.id
  });
  user.lastMessages = user.lastMessages.slice(-10); // Keep last 10 messages

  await user.save();
});

// ===== Message Update Event (for edited messages) =====
client.on("messageUpdate", async (oldMessage, newMessage) => {
  if (!newMessage.guild || newMessage.author.bot) return;
  if (oldMessage.content === newMessage.content) return;

  // Check edited message for violations
  const contentAnalysis = analyzeContent(newMessage.content);
  if (contentAnalysis.score > 0) {
    await newMessage.delete().catch(() => {});
    await handleViolation(newMessage, contentAnalysis.score, "Edited Message Violation", {
      oldContent: oldMessage.content?.substring(0, 100),
      patterns: contentAnalysis.reasons
    });
  }
});

// ===== Member Join Security =====
client.on("guildMemberAdd", async member => {
  const accountAge = Date.now() - member.user.createdTimestamp;
  const daysOld = accountAge / (1000 * 60 * 60 * 24);

  let suspicious = false;
  let reasons = [];

  // Check account age
  if (daysOld < config.suspiciousDays) {
    suspicious = true;
    reasons.push(`Account too new (${daysOld.toFixed(1)} days old)`);
  }

  // Check if account was created recently (last 24 hours)
  if (daysOld < 1) {
    suspicious = true;
    reasons.push("Account created within last 24 hours");
  }

  // Check for default avatar (often bots or throwaway accounts)
  if (member.user.avatar === null) {
    suspicious = true;
    reasons.push("Default avatar");
  }

  // Check username for suspicious patterns
  const username = member.user.username.toLowerCase();
  if (username.match(/^[a-zA-Z0-9]+\d{4,}$/)) { // Random letters + numbers
    suspicious = true;
    reasons.push("Suspicious username pattern");
  }

  if (username.includes("discord") || username.includes("moderator") || 
      username.includes("admin") || username.includes("security")) {
    suspicious = true;
    reasons.push("Impersonation attempt");
  }

  if (suspicious) {
    await User.findOneAndUpdate(
      { userId: member.id, guildId: member.guild.id },
      { 
        suspicious: true,
        suspiciousReasons: reasons,
        joinDate: new Date()
      },
      { upsert: true }
    );

    await logAction(member.guild, {
      type: 'WARNING',
      user: member.user,
      moderator: client.user,
      reason: 'Suspicious Account Detected',
      details: {
        accountAge: `${daysOld.toFixed(1)} days`,
        reasons: reasons.join(', ')
      }
    });

    // Auto-kick if extremely suspicious
    if (daysOld < 0.1 || username.match(/bot|spam|hack/i)) { // Less than 2.4 hours old
      await member.kick("Guardian: Extremely suspicious account").catch(() => {});
      await logAction(member.guild, {
        type: 'KICK',
        user: member.user,
        moderator: client.user,
        reason: 'Extremely suspicious account (automatic protection)',
        details: {
          accountAge: `${daysOld.toFixed(1)} days`,
          reasons: reasons.join(', ')
        }
      });
    }
  }
});

// ===== Voice Channel Security =====
client.on("voiceStateUpdate", async (oldState, newState) => {
  if (!newState.guild) return;

  const member = newState.member;
  if (!member) return;

  // Check for voice channel raids
  if (newState.channelId && !oldState.channelId) {
    // User joined a voice channel
    const voiceStates = newState.guild.channels.cache.get(newState.channelId)?.members.size || 0;
    
    if (voiceStates > 25) { // Large voice channel
      const user = await User.findOne({
        userId: member.id,
        guildId: newState.guild.id
      });

      if (user && user.suspicious) {
        // Disconnect suspicious users from large voice channels
        await newState.disconnect("Guardian: Voice channel protection").catch(() => {});
        await logAction(newState.guild, {
          type: 'WARNING',
          user: member.user,
          moderator: client.user,
          reason: 'Voice channel protection - Suspicious user in large voice channel',
          details: {
            channel: newState.channelId,
            userCount: voiceStates
          }
        });
      }
    }
  }
});

// ===== Periodic Cleanup and Points Decay =====
setInterval(async () => {
  try {
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    
    // Decay points for users who haven't violated in a week
    await User.updateMany(
      { lastViolation: { $lt: oneWeekAgo }, points: { $gt: 0 } },
      { $mul: { points: 0.9 } } // Reduce points by 10%
    );

    // Reset multiplier for inactive users
    await User.updateMany(
      { lastViolation: { $lt: oneWeekAgo } },
      { multiplier: 1 }
    );

    console.log('Periodic cleanup completed');
  } catch (error) {
    console.error('Error in periodic cleanup:', error);
  }
}, 24 * 60 * 60 * 1000); // Run daily

// ===== Command Handler for Log Channel =====
client.on("messageCreate", async message => {
  if (message.author.bot) return;
  if (!message.member?.permissions.has(PermissionsBitField.Flags.Administrator)) return;

  if (message.content.startsWith("!setlog")) {
    const channel = message.mentions.channels.first();
    if (!channel || channel.type !== ChannelType.GuildText) {
      return message.reply("Please mention a valid text channel!");
    }

    // Update the log channel ID (you might want to store this in config/database)
    // For now, we'll just reply
    await message.reply(`✅ Log channel set to ${channel}`);
  }
});

client.login(process.env.TOKEN);
