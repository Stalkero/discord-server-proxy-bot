const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const { Server } = require('socket.io');
const http = require('http');
const multer = require('multer');
const dotenv = require('dotenv');
const { Client, GatewayIntentBits, AttachmentBuilder, Partials } = require('discord.js');
const passport = require('passport');
const DiscordStrategy = require('passport-discord');

dotenv.config();

// Load environment variables from .env file
const {
  DISCORD_TOKEN,
  OAUTH_CLIENT_ID,
  OAUTH_CLIENT_SECRET,
  OAUTH_CALLBACK,
  ADMIN_IDS,
  CHANNEL_ID,
  PORT = 3000
} = process.env;



const app = express();
const server = http.createServer(app);
const io = new Server(server);


app.use(bodyParser.json());
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());


// Load users from JSON file or create an empty object
const users = fs.existsSync('users.json') ? JSON.parse(fs.readFileSync('users.json')) : {};
const saveUsers = () => {
  try {
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
    console.log('[INFO] users.json saved');
  } catch (err) {
    console.error('[ERROR] Failed to write users.json:', err);
  }
};


// Load message history from JSON file or create an empty object
const messageHistoryByChannel = fs.existsSync('messages.json')
  ? JSON.parse(fs.readFileSync('messages.json'))
  : {};
const saveMessages = () => fs.writeFileSync('messages.json', JSON.stringify(messageHistoryByChannel, null, 2));



// Discord bot
const bot = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildPresences
  ],
  partials: [Partials.Channel]
});



// Passport OAuth
passport.serializeUser((user, done) => {
  if (!user) return done(new Error('No user to serialize'));
  console.log(`[DEBUG] Admin logged in: ${user.username} (${user.id})`);
  done(null, user);
});



passport.deserializeUser((user, done) => done(null, user));



passport.use(new DiscordStrategy({
  authorizationURL: 'https://discord.com/oauth2/authorize',
  tokenURL: 'https://discord.com/api/oauth2/token',
  clientID: OAUTH_CLIENT_ID,
  clientSecret: OAUTH_CLIENT_SECRET,
  callbackURL: OAUTH_CALLBACK,
  scope: ['identify']
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));


// Middleware to ensure user is authenticated
const ensureAuthenticated = (req, res, next) => {
  if (req.session.user) return next();
  res.sendStatus(403);
};



// Middleware to ensure user is an admin
const ensureAdmin = (req, res, next) => {
  if (req.isAuthenticated() && ADMIN_IDS.split(',').includes(req.user.id)) return next();
  res.sendStatus(403);
};



// Static + middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/', (req, res) => res.redirect('/login.html'));

// Local login/logout
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user || !user.password) return res.sendStatus(401);

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return res.sendStatus(401);

  req.session.user = { username, prefix: user.prefix };
  console.log(`[DEBUG] User logged in: ${username}`);
  res.sendStatus(200);
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login.html')));




// Discord admin login
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', {
  failureRedirect: '/admin-login-failed.html'
}), (req, res) => res.redirect('/admin.html'));




// Admin APIs
app.get('/api/users', ensureAdmin, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const out = {};
  for (const [k, v] of Object.entries(users)) out[k] = { prefix: v.prefix };
  res.json(out);
});



// Admin APIs
app.post('/api/users', ensureAdmin, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const { username, password, prefix } = req.body;
  users[username] = { password: bcrypt.hashSync(password, 10), prefix };
  saveUsers();
  res.sendStatus(201);
});



// Admin APIs
app.post('/api/reset-password', ensureAdmin, (req, res) => {
  const { username, password } = req.body;

  if (!users[username]) {
    console.warn(`[WARN] Tried to reset non-existent user: ${username}`);
    return res.sendStatus(404);
  }

  if (!password || password.length < 3) {
    return res.status(400).send('Password is required and must be at least 3 characters');
  }

  try {
    const hashed = bcrypt.hashSync(password, 10);
    users[username].password = hashed;
    saveUsers(); 
    console.log(`[INFO] Password reset for ${username}`);
    res.sendStatus(200);
  } catch (err) {
    console.error('[ERROR] Password reset failed:', err);
    res.sendStatus(500);
  }
});


// Admin APIs
app.delete('/api/users/:username', ensureAdmin, (req, res) => {
  if (!users[req.params.username]) return res.sendStatus(404);
  delete users[req.params.username];
  saveUsers();
  res.sendStatus(200);
});



// Authenticated APIs
app.get('/session-info', ensureAuthenticated, (req, res) => {
  res.json({ username: req.session.user?.prefix || req.session.user?.username || 'Unknown' });
});

app.get('/channels', ensureAuthenticated, async (req, res) => {
  const guild = bot.guilds.cache.first();
  const channels = guild ? guild.channels.cache
    .filter(c => c.isTextBased() && c.viewable)
    .map(c => ({ id: c.id, name: c.name })) : [];
  res.json(channels);
});

app.get('/messages', ensureAuthenticated, (req, res) => {
  const { all, channelId } = req.query;

  if (all === 'true') {
    const allMessages = Object.values(messageHistoryByChannel)
      .flat()
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    return res.json(allMessages);
  }

  const id = channelId || CHANNEL_ID;
  return res.json(messageHistoryByChannel[id] || []);
});



// Fetch online users from Discord
app.get('/discord-online', ensureAuthenticated, async (req, res) => {
  try {
    const guild = bot.guilds.cache.first();
    await guild.members.fetch();

    const online = guild.members.cache
      .filter(m => !m.user.bot && ['online', 'idle', 'dnd'].includes(m.presence?.status))
      .map(m => m.displayName);

    res.json(online);
  } catch (err) {
    console.error('Error fetching Discord online users:', err);
    res.status(500).json([]);
  }
});



// Send message to Discord channel

app.post('/send', ensureAuthenticated, async (req, res) => {
  const { message, channelId } = req.body;
  const channel = bot.channels.cache.get(channelId || CHANNEL_ID);
  if (!channel) return res.sendStatus(400);

  const msgObj = {
    user: req.session.user.prefix,
    text: message,
    timestamp: new Date().toISOString(),
    channelId: channel.id
  };

  messageHistoryByChannel[channel.id] = messageHistoryByChannel[channel.id] || [];
  messageHistoryByChannel[channel.id].push(msgObj);
  messageHistoryByChannel[channel.id] = messageHistoryByChannel[channel.id].slice(-500);
  saveMessages();
  io.emit('chat message', msgObj);

  await channel.send(`[${req.session.user.prefix}]: ${message}`);
  res.sendStatus(200);
});



// File upload
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext).replace(/\s+/g, '_');
    const unique = `${base}-${Date.now()}${ext}`;
    cb(null, unique);
  }
});
const upload = multer({ storage });



// File upload API
app.post('/upload', ensureAuthenticated, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');

  const channelId = req.body.channelId || CHANNEL_ID;
  const localPath = path.join(__dirname, 'uploads', req.file.filename);
  const url = `/uploads/${req.file.filename}`;
  const channel = bot.channels.cache.get(channelId);
  if (!channel) return res.status(500).send('Channel not found');

  try {
    const attachment = new AttachmentBuilder(localPath);
    await channel.send({
      content: `[${req.session.user.prefix}] uploaded a file:`,
      files: [attachment]
    });

    const msg = {
      user: req.session.user.prefix,
      text: `<img src="${url}" alt="image">`,
      timestamp: new Date().toISOString(),
      channelId
    };

    messageHistoryByChannel[channelId] = messageHistoryByChannel[channelId] || [];
    messageHistoryByChannel[channelId].push(msg);
    messageHistoryByChannel[channelId] = messageHistoryByChannel[channelId].slice(-500);
    saveMessages();
    io.emit('chat message', msg);

    res.json({ url });

    // 🔥 Clean up the uploaded file AFTER everything succeeds
    fs.unlink(localPath, (err) => {
      if (err) console.warn('Failed to delete uploaded file:', err);
    });

  } catch (err) {
    console.error('Upload failed:', err);
    res.sendStatus(500);
  }
});



// Real-time Socket.IO
const onlineUsers = {};

io.on('connection', (socket) => {
  console.log(`[DEBUG] Socket connected: ${socket.id}`);

  socket.on('registerUser', (username) => {
    onlineUsers[socket.id] = username;
    io.emit('online users', Object.values(onlineUsers));
  });

  socket.on('disconnect', () => {
    delete onlineUsers[socket.id];
    io.emit('online users', Object.values(onlineUsers));
  });

  socket.on('typing', (data) => {
    socket.broadcast.emit('user typing', data);
  });

  socket.on('stop typing', (data) => {
    socket.broadcast.emit('user stop typing', data);
  });
});



// Discord events
async function fetchChannelHistory() {
  try {
    const channel = await bot.channels.fetch(CHANNEL_ID);
    const messages = await channel.messages.fetch({ limit: 100 });
    const recent = Array.from(messages.values())
      .filter(m => !m.author.bot)
      .map(m => ({
        user: m.member?.nickname || m.author.username,
        text: m.content,
        timestamp: m.createdAt.toISOString(),
        channelId: channel.id
      }))
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    messageHistoryByChannel[channel.id] = messageHistoryByChannel[channel.id] || [];
    messageHistoryByChannel[channel.id].push(...recent);
    messageHistoryByChannel[channel.id] = messageHistoryByChannel[channel.id].slice(-500);
    saveMessages();
    console.log(`[INFO] Fetched ${recent.length} messages from Discord history.`);
  } catch (err) {
    console.error('[ERROR] Fetching Discord history failed:', err.message);
  }
}

bot.once('ready', async () => {
  console.log(`Logged in as ${bot.user.tag}`);
  await fetchChannelHistory();
});

bot.on('messageCreate', (msg) => {
  if (msg.author.bot || !msg.guild) return;

  let content = msg.content;

  // Replace Discord mentions with readable names
  content = content.replace(/<@!?(\d+)>/g, (match, userId) => {
    const member = msg.guild.members.cache.get(userId);
    return member ? `@${member.displayName}` : match;
  });

  const msgObj = {
    user: msg.member?.nickname || msg.author.username,
    text: content,
    timestamp: msg.createdAt.toISOString(),
    channelId: msg.channel.id
  };

  messageHistoryByChannel[msg.channel.id] = messageHistoryByChannel[msg.channel.id] || [];
  messageHistoryByChannel[msg.channel.id].push(msgObj);
  messageHistoryByChannel[msg.channel.id] = messageHistoryByChannel[msg.channel.id].slice(-500);
  saveMessages();
  io.emit('chat message', msgObj);
});



//Start server and Discord bot
bot.login(DISCORD_TOKEN);
server.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
