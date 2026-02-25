const { Client, GatewayIntentBits, PermissionsBitField, EmbedBuilder, ChannelType } = require("discord.js");
const mongoose = require("mongoose");
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

// ===== Configuration Default =====
const config = {
  spamInterval: 5000, // 5 seconds
  spamLimit: 5, // 5 messages
  maxAttachmentMB: 8, // 8 MB
  suspiciousDays: 7, // 7 days
  severity: {
    toxic: {
      indonesian: 4,
      english: 3,
      spanish: 3,
      arabic: 4,
      repeated: 2,
      zalgo: 3
    },
    harassment: {
      personal: 5,
      threatening: 8,
      doxxing: 10
    },
    scam: {
      links: 6,
      ipGrabber: 8,
      crypto: 7,
      nsfw: 10
    },
    advertising: {
      server: 4,
      social: 2,
      selling: 5
    }
  }
};

// ===== MongoDB Connect =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ===== Log Channel Configuration =====
const LOG_CHANNEL_ID = '1359068998544789645'; // Channel ID untuk log

// ===== Check Bot Permissions =====
function checkBotPermissions(member) {
  if (!member.guild.members.me) return false;
  
  const botMember = member.guild.members.me;
  const requiredPermissions = [
    PermissionsBitField.Flags.ModerateMembers, // Timeout
    PermissionsBitField.Flags.BanMembers,      // Ban
    PermissionsBitField.Flags.KickMembers,      // Kick
    PermissionsBitField.Flags.ManageMessages    // Delete messages
  ];
  
  const missingPermissions = requiredPermissions.filter(
    perm => !botMember.permissions.has(perm)
  );
  
  return {
    hasPermissions: missingPermissions.length === 0,
    missingPermissions: missingPermissions
  };
}

// ===== Enhanced Toxic Detection with ML-like scoring =====
function analyzeContent(content) {
  const patterns = {
    toxic: {
      indonesian: /kontol|anjing|babi|ngentot|memek|goblok|bodoh|tolol|ngentod|jancok|asu|bangsat|bajingan|kampret|dongo|belegug|pepek|tempik|pantek|tai|ngentot|ngntd|njir|ngawi|goblok|bego|geblek|congor|monyet|kadull|kampang|jembut|kimak|pukimak|bangsad|ngentod|kontl|anjg|anj|mmk|ngnt/i,
      english: /fuck|bitch|asshole|motherfucker|nigger|shit|damn|piss off|cunt|dickhead|bastard|wanker|twat|prick|whore|slut|retard|faggot|dumbass|jackass|dipshit|douchebag|cocksucker|pussy|asshat|asswipe/i,
      spanish: /puta|mierda|pendejo|cabron|verga|cojones|chingar|carajo|concha|gilipollas|hijoputa|maricon|puto|coño|joder/i,
      arabic: /كسم|شرموطة|متناك|ابن الكلب|كس امك|نيق|شرموط|كس|طيز|عاهرة|قحبة|منيوك|خول/i,
      repeated: /(.)\1{8,}/i,
      zalgo: /[̗̙̖̬̥̰̜̼͔͕̼̘̮͚̻̲̝̺̦̱̞̠̤̩̙̘̮̲̫̬̦͓]/
    },
    harassment: {
      personal: /\bkamu (jelek|bodoh|goblok|bego|tolol|idiot)\b|\byou (are )?(ugly|stupid|dumb|idiot|retarded)\b/i,
      threatening: /\b(saya akan|gua bakal|gue bakal|i will|im gonna|i'm gonna) (bunuh|kill|hajar|beat|destroy|habisi|mutilasi|tusuk|tembak)\b/i,
      doxxing: /\b(alamat|address|rumah|house|tinggal di|live at) .{0,20}(jalan|jl|street|rt|rw|desa|kota|city)\b|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
    },
    scam: {
      links: /\b(bit\.ly|tinyurl|discord\.gift|discord\.com\/gifts|free nitro|steamcommunity\.com\/offer|free robux|free v-bucks|airdrop|giveaway.*(nitro|robux)|hacked account|account generator|boost your server|nitro gift)\b/i,
      ipGrabber: /http:\/\/\d+\.\d+\.\d+\.\d+:\d+|\d+\.\d+\.\d+\.\d+\/grab|iplogger|grabify|ps3cfw|ip-tracker/i,
      crypto: /\b(free|bonus|double|gratis) (bitcoin|ethereum|crypto|btc|eth|dogecoin)\b|\bdouble your (bitcoin|money|eth)\b/i,
      nsfw: /\b(underage|teen.*(porn|sex)|loli|shota|cp|child porn|bocah|anak di bawah umur)\b/i
    },
    advertising: {
      server: /discord\.gg\/[a-zA-Z0-9]+|discord\.com\/invite\/[a-zA-Z0-9]+/i,
      social: /\b(youtube|instagram|tiktok|twitter|facebook|snapchat)\.com\/[a-zA-Z0-9_.-]+\b/i,
      selling: /\b(jual|selling|beli|buying|tukar|trade) (jasa|service|akun|account|boost|nitro|level|rank|joki|jocky)\b|\bprice \$\d+\b|\bharga (rp|ribu|juta)\b/i
    }
  };

  let score = 0;
  let reasons = [];

  // Check each category
  for (const [category, subPatterns] of Object.entries(patterns)) {
    for (const [type, pattern] of Object.entries(subPatterns)) {
      if (pattern.test(content)) {
        const severityScore = config.severity[category]?.[type] || 2;
        score += severityScore;
        reasons.push(`${category}:${type}`);
      }
    }
  }

  // Check for excessive caps
  const letters = content.replace(/[^A-Za-z]/g, '');
  const capsCount = (content.match(/[A-Z]/g) || []).length;
  if (letters.length > 5 && capsCount / letters.length > 0.7) {
    score += 2;
    reasons.push("excessive_caps");
  }

  // Check for mass mentions
  const mentionCount = (content.match(/<@!?&\d+>/g) || []).length;
  if (mentionCount > 3) {
    score += mentionCount * 1.5;
    reasons.push("mass_mentions");
  }

  // Check for link shorteners
  const shorteners = /bit\.ly|tinyurl|shorturl|shorte|ow\.ly|goo\.gl|is\.gd|buff\.ly|short\.link|shortened/i;
  if (shorteners.test(content)) {
    score += 3;
    reasons.push("link_shortener");
  }

  return { score, reasons };
}

// ===== Spam Detection =====
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

    const recentMessages = userMessages.filter(m => now - m.timestamp < config.spamInterval);
    this.messageCache.set(userId, recentMessages);

    let score = 0;
    let reasons = [];

    if (recentMessages.length >= config.spamLimit) {
      score += 3;
      reasons.push("rapid_messages");
    }

    const contentCount = recentMessages.filter(m => m.content === message.content).length;
    if (contentCount >= 3) {
      score += contentCount;
      reasons.push("message_repetition");
    }

    const uniqueChannels = new Set(recentMessages.map(m => m.channelId)).size;
    if (uniqueChannels >= 3 && recentMessages.length >= 5) {
      score += 4;
      reasons.push("cross_channel_spam");
    }

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

// ===== Handle Violation =====
async function handleViolation(message, severity, reason, additionalInfo = {}) {
  if (!message.member) return;

  try {
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

    if (user.lastViolation) {
      const hoursSinceLastViolation = (now - user.lastViolation) / (1000 * 60 * 60);
      
      if (hoursSinceLastViolation < 48) {
        user.multiplier = (user.multiplier || 1) + 0.5;
      } else if (hoursSinceLastViolation > 168) {
        user.multiplier = Math.max(1, (user.multiplier || 1) - 0.5);
      }
    } else {
      user.multiplier = 1;
    }

    if (user.suspicious) {
      user.multiplier *= 1.5;
    }

    if (!user.points) user.points = 0;
    
    const points = severity * (user.multiplier || 1);
    user.points += points;
    user.lastViolation = now;
    
    if (!user.offenseHistory) user.offenseHistory = [];
    
    user.offenseHistory.push({
      reason: reason,
      timestamp: now,
      severity: severity,
      points: points
    });

    await user.save();

    await logAction(message.guild, {
      type: 'WARNING',
      user: message.author,
      moderator: client.user,
      reason: reason,
      details: additionalInfo,
      points: points,
      totalPoints: user.points
    });

    // Check permissions before punishing
    const permCheck = checkBotPermissions(message.member);
    if (!permCheck.hasPermissions) {
      await logAction(message.guild, {
        type: 'WARNING',
        user: client.user,
        moderator: client.user,
        reason: 'Missing Permissions',
        details: {
          missingPermissions: permCheck.missingPermissions.map(p => p.toString()).join(', '),
          action: 'Cannot punish user'
        }
      });
      return;
    }

    await punish(message.member, user.points, reason);
    
  } catch (error) {
    console.error('Error in handleViolation:', error);
  }
}

// ===== Enhanced Punishment System with better error handling =====
async function punish(member, points, lastReason) {
  if (!member) return;

  let action = null;
  let duration = null;

  try {
    // Check if member is moderatable
    if (!member.moderatable) {
      await logAction(member.guild, {
        type: 'WARNING',
        user: member.user,
        moderator: client.user,
        reason: 'Cannot punish - User has higher permissions than bot',
        details: {
          points: points,
          attemptedAction: getActionFromPoints(points)
        }
      });
      return;
    }

    if (points >= 100) {
      if (member.bannable) {
        await member.ban({ reason: `Guardian: Permanent Ban - ${lastReason}` });
        action = 'PERMANENT_BAN';
      }
    } else if (points >= 75) {
      if (member.bannable) {
        await member.ban({ reason: `Guardian: 6 Month Ban - ${lastReason}` });
        action = 'SIX_MONTH_BAN';
      }
    } else if (points >= 50) {
      if (member.bannable) {
        await member.ban({ reason: `Guardian: 1 Month Ban - ${lastReason}` });
        action = 'ONE_MONTH_BAN';
      }
    } else if (points >= 35) {
      if (member.bannable) {
        await member.ban({ reason: `Guardian: 1 Week Ban - ${lastReason}` });
        action = 'ONE_WEEK_BAN';
      }
    } else if (points >= 25) {
      if (member.moderatable) {
        await member.timeout(14 * 24 * 60 * 60 * 1000, `Guardian: 2 Week Timeout - ${lastReason}`);
        action = 'TWO_WEEK_TIMEOUT';
        duration = '14 days';
      }
    } else if (points >= 20) {
      if (member.moderatable) {
        await member.timeout(7 * 24 * 60 * 60 * 1000, `Guardian: 1 Week Timeout - ${lastReason}`);
        action = 'ONE_WEEK_TIMEOUT';
        duration = '7 days';
      }
    } else if (points >= 15) {
      if (member.moderatable) {
        await member.timeout(3 * 24 * 60 * 60 * 1000, `Guardian: 3 Day Timeout - ${lastReason}`);
        action = 'THREE_DAY_TIMEOUT';
        duration = '3 days';
      }
    } else if (points >= 10) {
      if (member.moderatable) {
        await member.timeout(24 * 60 * 60 * 1000, `Guardian: 24 Hour Timeout - ${lastReason}`);
        action = 'DAY_TIMEOUT';
        duration = '24 hours';
      }
    } else if (points >= 5) {
      if (member.moderatable) {
        await member.timeout(60 * 60 * 1000, `Guardian: 1 Hour Timeout - ${lastReason}`);
        action = 'HOUR_TIMEOUT';
        duration = '1 hour';
      }
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
  } catch (error) {
    console.error('Error in punish:', error);
    
    // Log the error
    await logAction(member.guild, {
      type: 'WARNING',
      user: member.user,
      moderator: client.user,
      reason: 'Failed to apply punishment',
      details: {
        error: error.message,
        points: points,
        attemptedAction: getActionFromPoints(points)
      }
    });
  }
}

function getActionFromPoints(points) {
  if (points >= 100) return 'PERMANENT_BAN';
  if (points >= 75) return 'SIX_MONTH_BAN';
  if (points >= 50) return 'ONE_MONTH_BAN';
  if (points >= 35) return 'ONE_WEEK_BAN';
  if (points >= 25) return 'TWO_WEEK_TIMEOUT';
  if (points >= 20) return 'ONE_WEEK_TIMEOUT';
  if (points >= 15) return 'THREE_DAY_TIMEOUT';
  if (points >= 10) return 'DAY_TIMEOUT';
  if (points >= 5) return 'HOUR_TIMEOUT';
  return 'NO_ACTION';
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

    embed.addFields({ 
      name: '👤 User', 
      value: `${data.user.tag} (<@${data.user.id}>)`, 
      inline: true 
    });

    if (data.moderator) {
      embed.addFields({ 
        name: '🛡️ Moderator', 
        value: `${data.moderator.tag}`, 
        inline: true 
      });
    }

    embed.addFields({ 
      name: '📝 Reason', 
      value: data.reason || 'No reason provided', 
      inline: false 
    });

    if (data.points) {
      embed.addFields({ 
        name: '⚡ Points', 
        value: `${data.points.toFixed(1)}`, 
        inline: true 
      });
    }

    if (data.totalPoints) {
      embed.addFields({ 
        name: '📊 Total Points', 
        value: `${data.totalPoints.toFixed(1)}`, 
        inline: true 
      });
    }

    if (data.duration) {
      embed.addFields({ 
        name: '⏱️ Duration', 
        value: data.duration, 
        inline: true 
      });
    }

    if (data.details && Object.keys(data.details).length > 0) {
      const detailsStr = Object.entries(data.details)
        .map(([k, v]) => `**${k}:** ${v}`)
        .join('\n');
      embed.addFields({ 
        name: '📋 Additional Details', 
        value: detailsStr.substring(0, 1000), 
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

// ===== Message Event =====
client.on("messageCreate", async message => {
  if (message.author.bot) return;
  if (!message.guild) return;

  try {
    // Check for invites
    if (message.content.includes("discord.gg/") || message.content.includes("discord.com/invite/")) {
      try {
        const inviteMatch = message.content.match(/(?:discord\.gg\/|discord\.com\/invite\/)([a-zA-Z0-9]+)/);
        if (inviteMatch) {
          const inviteCode = inviteMatch[1];
          const invite = await client.fetchInvite(inviteCode).catch(() => null);
          
          if (invite && invite.guild) {
            const suspiciousNames = /hack|cheat|free nitro|boost|nuke|raid|spam|cp|child|underage/i;
            if (suspiciousNames.test(invite.guild.name) || invite.memberCount > 10000) {
              
              await message.delete().catch(() => {});
              await handleViolation(message, 6, "Suspicious Server Invite", {
                serverName: invite.guild.name.substring(0, 50),
                memberCount: invite.memberCount
              });
              return;
            }
          }
        }
      } catch (error) {
        await message.delete().catch(() => {});
        await handleViolation(message, 4, "Invalid/Unknown Invite");
        return;
      }
    }

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

    if (!user.messageTimestamps) user.messageTimestamps = [];
    user.messageTimestamps.push(now);
    user.messageTimestamps = user.messageTimestamps.filter(
      t => now - t < config.spamInterval
    );

    if (user.messageTimestamps.length >= config.spamLimit) {
      await message.delete().catch(() => {});
      await handleViolation(message, 3, "Spam");
      return;
    }

    const spamResult = spamDetector.checkSpam(message);
    if (spamResult.score > 0) {
      await message.delete().catch(() => {});
      await handleViolation(message, spamResult.score, "Spam Detection", {
        patterns: spamResult.reasons.join(', ')
      });
      return;
    }

    const contentAnalysis = analyzeContent(message.content);
    if (contentAnalysis.score > 0) {
      await message.delete().catch(() => {});
      await handleViolation(message, contentAnalysis.score, "Content Violation", {
        patterns: contentAnalysis.reasons.join(', ')
      });
      return;
    }

    if (message.attachments.size > 0) {
      for (const attachment of message.attachments.values()) {
        if (attachment.size > config.maxAttachmentMB * 1024 * 1024) {
          await message.delete().catch(() => {});
          await handleViolation(message, 4, "Large Attachment", {
            fileName: attachment.name,
            sizeMB: (attachment.size / (1024 * 1024)).toFixed(2)
          });
          return;
        }

        const dangerousExtensions = ['.exe', '.msi', '.bat', '.cmd', '.sh', '.jar', '.vbs', '.ps1', '.scr', '.dll', '.js', '.wsf'];
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

    if (!user.lastMessages) user.lastMessages = [];
    user.lastMessages.push({
      content: message.content.substring(0, 100),
      timestamp: now,
      messageId: message.id
    });
    user.lastMessages = user.lastMessages.slice(-10);

    await user.save();
  } catch (error) {
    console.error('Error in messageCreate:', error);
  }
});

// ===== Message Update Event =====
client.on("messageUpdate", async (oldMessage, newMessage) => {
  if (!newMessage.guild || newMessage.author?.bot) return;
  if (oldMessage.content === newMessage.content) return;

  try {
    const contentAnalysis = analyzeContent(newMessage.content);
    if (contentAnalysis.score > 0) {
      await newMessage.delete().catch(() => {});
      await handleViolation(newMessage, contentAnalysis.score, "Edited Message Violation", {
        oldContent: oldMessage.content?.substring(0, 100) || 'No old content',
        patterns: contentAnalysis.reasons.join(', ')
      });
    }
  } catch (error) {
    console.error('Error in messageUpdate:', error);
  }
});

// ===== Member Join Security =====
client.on("guildMemberAdd", async member => {
  try {
    const accountAge = Date.now() - member.user.createdTimestamp;
    const daysOld = accountAge / (1000 * 60 * 60 * 24);

    let suspicious = false;
    let reasons = [];

    if (daysOld < config.suspiciousDays) {
      suspicious = true;
      reasons.push(`Account too new (${daysOld.toFixed(1)} days old)`);
    }

    if (daysOld < 1) {
      suspicious = true;
      reasons.push("Account created within last 24 hours");
    }

    if (member.user.avatar === null) {
      suspicious = true;
      reasons.push("Default avatar");
    }

    const username = member.user.username.toLowerCase();
    if (username.match(/^[a-zA-Z0-9]+\d{4,}$/)) {
      suspicious = true;
      reasons.push("Suspicious username pattern");
    }

    if (username.includes("discord") || username.includes("moderator") || 
        username.includes("admin") || username.includes("security") ||
        username.includes("staff") || username.includes("helper")) {
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

      if (daysOld < 0.1 || username.match(/bot|spam|hack|nuke|raid/i)) {
        if (member.kickable) {
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
    }
  } catch (error) {
    console.error('Error in guildMemberAdd:', error);
  }
});

// ===== Voice Channel Security =====
client.on("voiceStateUpdate", async (oldState, newState) => {
  if (!newState.guild) return;

  try {
    const member = newState.member;
    if (!member) return;

    if (newState.channelId && !oldState.channelId) {
      const voiceStates = newState.guild.channels.cache.get(newState.channelId)?.members.size || 0;
      
      if (voiceStates > 25) {
        const user = await User.findOne({
          userId: member.id,
          guildId: newState.guild.id
        });

        if (user && user.suspicious) {
          if (member.moderatable) {
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
    }
  } catch (error) {
    console.error('Error in voiceStateUpdate:', error);
  }
});

// ===== Periodic Cleanup =====
setInterval(async () => {
  try {
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    
    await User.updateMany(
      { lastViolation: { $lt: oneWeekAgo }, points: { $gt: 0 } },
      { $mul: { points: 0.9 } }
    );

    await User.updateMany(
      { lastViolation: { $lt: oneWeekAgo } },
      { multiplier: 1 }
    );

    console.log('Periodic cleanup completed');
  } catch (error) {
    console.error('Error in periodic cleanup:', error);
  }
}, 24 * 60 * 60 * 1000);

// ===== Ready Event =====
client.once('ready', () => {
  console.log(`Logged in as ${client.user.tag}`);
  
  // Log bot permissions
  client.guilds.cache.forEach(guild => {
    const botMember = guild.members.me;
    if (botMember) {
      const permissions = botMember.permissions.toArray();
      console.log(`[${guild.name}] Bot permissions:`, permissions);
      
      // Check if bot has required permissions
      const hasModerate = botMember.permissions.has(PermissionsBitField.Flags.ModerateMembers);
      const hasBan = botMember.permissions.has(PermissionsBitField.Flags.BanMembers);
      const hasKick = botMember.permissions.has(PermissionsBitField.Flags.KickMembers);
      
      if (!hasModerate || !hasBan || !hasKick) {
        console.log(`⚠️  [${guild.name}] Bot missing moderation permissions!`);
        console.log(`   Moderate Members: ${hasModerate ? '✅' : '❌'}`);
        console.log(`   Ban Members: ${hasBan ? '✅' : '❌'}`);
        console.log(`   Kick Members: ${hasKick ? '✅' : '❌'}`);
      }
    }
  });
});

// ===== Error Handling =====
process.on('unhandledRejection', error => {
  console.error('Unhandled promise rejection:', error);
});

client.login(process.env.TOKEN);
