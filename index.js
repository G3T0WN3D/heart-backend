// app.js — Heart Dating App (alles-in-1, zonder routers)

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
require('dotenv').config();
const Database = require('./classes/database.js');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcrypt');

// === App & middleware ===
const app = express();

app.use(
  cors({
    origin: 'http://localhost:8080',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

app.use(bodyParser.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'heart_session_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true },
  })
);

// === Static files (uploaded images) ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'images')),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname).toLowerCase(); // .jpg/.png
    cb(null, unique + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const ok = ['image/jpeg','image/png','image/webp','image/gif'].includes(file.mimetype);
  cb(null, ok);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

app.use('/images', express.static(path.join(__dirname, 'images')));


// === Database ===
const db = new Database();

// ====== Helpers ======

/** Converteer YYYY-MM-DD naar leeftijd in jaren in SQL via TIMESTAMPDIFF in queries (zie endpoints). */

/** Consistente ordering voor match-paar (laagste id eerst) */
function orderPair(a, b) {
  return Number(a) < Number(b) ? [Number(a), Number(b)] : [Number(b), Number(a)];
}

/** Basis check of user deel uitmaakt van match */
async function userInMatch(matchId, userId) {
  const rows = await db.getQuery(
    'SELECT id FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?) LIMIT 1',
    [matchId, userId, userId]
  );
  return rows.length > 0;
}

// ====== Auth ======

// POST /register  { email, username, password, [bio, gender, birthdate, location] }
app.post('/register', async (req, res) => {
  try {
    const { email, username, password, bio, gender, birthdate, location } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Email, username en password zijn verplicht.' });
    }

    // Bestaat gebruiker al?
    const exists = await db.getQuery('SELECT id FROM users WHERE email = ? OR username = ?', [
      email,
      username,
    ]);
    if (exists.length) {
      return res.status(409).json({ message: 'Email of username is al in gebruik.' });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await db.getQuery(
      `INSERT INTO users (email, password_hash, username, bio, gender, birthdate, location)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email, hash, username, bio || null, gender || null, birthdate || null, location || null]
    );

    return res.status(201).json({ message: 'Registratie gelukt', userId: result.insertId });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Serverfout bij registreren.' });
  }
});

// GET /admin/users?adminId=...
app.get('/admin/users', async (req, res) => {
  try {
    const { adminId } = req.query;
    const check = await db.getQuery('SELECT is_admin FROM users WHERE id = ? LIMIT 1', [adminId]);
    if (!check.length || !check[0].is_admin) {
      return res.status(403).json({ message: 'Geen toegang. Geen admin.' });
    }

    const users = await db.getQuery(`
      SELECT 
        u.id, u.username, u.email, u.gender,
        DATE_FORMAT(u.birthdate, '%Y-%m-%d') AS birthdate,
        u.location, u.bio,
        (SELECT photo_url FROM user_photos WHERE user_id = u.id LIMIT 1) AS photo
      FROM users u
      WHERE u.is_admin = FALSE
      ORDER BY u.created_at DESC
    `);

    res.json(users);
  } catch (err) {
    console.error('Admin GET users error:', err);
    res.status(500).json({ message: 'Serverfout bij ophalen gebruikers.' });
  }
});


// POST /login  { email, password }
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email en password zijn verplicht.' });

    const users = await db.getQuery(
      'SELECT id, password_hash, banned, is_admin FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (!users.length)
      return res.status(401).json({ message: 'Ongeldige login.' });

    const user = users[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok)
      return res.status(401).json({ message: 'Ongeldige login.' });

    if (user.banned)
      return res.status(403).json({ message: 'Dit account is geblokkeerd.' });

    // Zet userId in sessie voor verdere requests
    req.session.userId = user.id;

    return res.json({
      message: 'Login ok',
      userId: user.id,
      is_admin: user.is_admin
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Serverfout bij inloggen.' });
  }
});


// POST /logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: 'Fout bij uitloggen.' });
    res.json({ message: 'Uitgelogd.' });
  });
});

// GET /me?userId=123  -> huidige profielgegevens ophalen
app.get('/me', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ message: 'userId is vereist.' });

    const rows = await db.getQuery(
      `SELECT 
         u.id, u.email, u.username, u.bio, u.gender,
         DATE_FORMAT(u.birthdate, '%Y-%m-%d') AS birthdate,
         u.location, u.is_admin,
         (SELECT photo_url FROM user_photos p WHERE p.user_id = u.id LIMIT 1) AS photo
       FROM users u
       WHERE u.id = ? 
       LIMIT 1`,
      [userId]
    );

    if (!rows.length) return res.status(404).json({ message: 'Gebruiker niet gevonden.' });

    res.json(rows[0]);
  } catch (err) {
    console.error('GetMe error:', err);
    res.status(500).json({ message: 'Serverfout bij ophalen profiel.' });
  }
});




// ====== Profiel ======

// GET /profiles?userId=ME&gender=female&min_age=20&max_age=35
// Haal kandidaten op, excl. jezelf en excl. al-geswipete profielen (optioneel), met 1ste foto.
app.get('/profiles', async (req, res) => {
  try {
    const { userId, gender, min_age, max_age, location } = req.query;
    if (!userId) return res.status(400).json({ message: 'userId is vereist.' });

    const params = [userId];

    // Basis select + eerste foto
    let sql = `
      SELECT 
        u.id, u.username, u.bio, u.gender,
        DATE_FORMAT(u.birthdate, '%Y-%m-%d') AS birthdate,
        u.location,
        (SELECT photo_url FROM user_photos p WHERE p.user_id = u.id LIMIT 1) AS photo
      FROM users u
      WHERE u.id <> ?
    `;


    // Filters
    if (gender) {
      sql += ` AND u.gender = ?`;
      params.push(gender);
    }
    if (min_age) {
      sql += ` AND TIMESTAMPDIFF(YEAR, u.birthdate, CURDATE()) >= ?`;
      params.push(Number(min_age));
    }
    if (max_age) {
      sql += ` AND TIMESTAMPDIFF(YEAR, u.birthdate, CURDATE()) <= ?`;
      params.push(Number(max_age));
    }
    if (location) {
      sql += ` AND u.location LIKE ?`;
      params.push(`%${location}%`);
    }


    // (Optioneel) exclude al geswipete profielen door deze user
    sql += ` AND u.id NOT IN (SELECT target_id FROM swipes WHERE swiper_id = ?)`;
    params.push(userId);

    // Limit
    sql += ` ORDER BY u.created_at DESC LIMIT 50`;

    const rows = await db.getQuery(sql, params);
    return res.json(rows);
  } catch (err) {
    console.error('Profiles error:', err);
    return res.status(500).json({ message: 'Serverfout bij profielen ophalen.' });
  }
});

// PUT /update-profile  { userId, username, bio, gender, birthdate, location }
app.put('/update-profile', async (req, res) => {
  try {
    const { userId, username, bio, gender, birthdate, location } = req.body;
    if (!userId) return res.status(400).json({ message: 'userId is vereist.' });

    const updates = [];
    const params = [];

    if (username !== undefined) {
      updates.push('username = ?');
      params.push(username);
    }
    if (bio !== undefined) {
      updates.push('bio = ?');
      params.push(bio);
    }
    if (gender !== undefined) {
      updates.push('gender = ?');
      params.push(gender);
    }
    if (birthdate !== undefined) {
      updates.push('birthdate = ?');
      params.push(birthdate);
    }
    if (location !== undefined) {
      updates.push('location = ?');
      params.push(location);
    }

    if (!updates.length) {
      return res.status(400).json({ message: 'Geen velden om te updaten.' });
    }

    params.push(userId);
    await db.getQuery(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
    return res.json({ message: 'Profiel geüpdatet.' });
  } catch (err) {
    console.error('Update-profile error:', err);
    return res.status(500).json({ message: 'Serverfout bij profielupdate.' });
  }
});

// POST /upload-photo  (multipart form-data: { file: image, userId })
// Slaat bestand op in /images en voegt record toe in user_photos.photo_url = bestandsnaam
app.post('/upload-photo', upload.single('file'), async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId || !req.file) {
      return res.status(400).json({ message: 'userId en image file zijn verplicht.' });
    }

    const filename = req.file.filename; // bevat nu een extensie
    const result = await db.getQuery(
      'INSERT INTO user_photos (user_id, photo_url) VALUES (?, ?)',
      [userId, filename]
    );

    const publicUrl = `/images/${filename}`;
    res.status(201).json({
      message: 'Foto toegevoegd.',
      photoId: result.insertId,
      filename,
      url: publicUrl
    });
  } catch (err) {
    console.error('Upload-photo error:', err);
    res.status(500).json({ message: 'Serverfout bij foto upload.' });
  }
});


// ====== Swipen & Matches ======

// POST /swipe  { swiperId, targetId, direction }  direction = 'left' | 'right'
app.post('/swipe', async (req, res) => {
  try {
    const { swiperId, targetId, direction } = req.body;
    if (!swiperId || !targetId || !['left', 'right'].includes(direction)) {
      return res.status(400).json({ message: 'swiperId, targetId en geldige direction zijn vereist.' });
    }
    if (Number(swiperId) === Number(targetId)) {
      return res.status(400).json({ message: 'Je kan niet op jezelf swipen.' });
    }

    // Sla swipe op
    await db.getQuery(
      'INSERT INTO swipes (swiper_id, target_id, direction) VALUES (?, ?, ?)',
      [swiperId, targetId, direction]
    );

    // Als right: check of er een wederzijdse right bestaat => match
    if (direction === 'right') {
      const reverse = await db.getQuery(
        'SELECT id FROM swipes WHERE swiper_id = ? AND target_id = ? AND direction = ? LIMIT 1',
        [targetId, swiperId, 'right']
      );

      if (reverse.length) {
        // Bestaat match al?
        const [u1, u2] = orderPair(swiperId, targetId);
        const exists = await db.getQuery(
          'SELECT id FROM matches WHERE (user1_id = ? AND user2_id = ?) LIMIT 1',
          [u1, u2]
        );

        if (!exists.length) {
          const insert = await db.getQuery(
            'INSERT INTO matches (user1_id, user2_id) VALUES (?, ?)',
            [u1, u2]
          );
          return res.json({
            message: 'Swipe opgeslagen — MATCH!',
            matched: true,
            matchId: insert.insertId,
          });
        }
        return res.json({ message: 'Swipe opgeslagen — match bestond al.', matched: true });
      }
    }

    return res.json({ message: 'Swipe opgeslagen', matched: false });
  } catch (err) {
    console.error('Swipe error:', err);
    return res.status(500).json({ message: 'Serverfout bij swipen.' });
  }
});

// GET /matches?userId=ME
app.get('/matches', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ message: 'userId is vereist.' });

    const rows = await db.getQuery(
      `SELECT 
         m.id AS match_id, m.matched_at,
         CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END AS other_id,
         u.username, u.location,
         (SELECT photo_url FROM user_photos p WHERE p.user_id = u.id LIMIT 1) AS photo
       FROM matches m
       JOIN users u ON u.id = CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END
       WHERE m.user1_id = ? OR m.user2_id = ?
       ORDER BY m.matched_at DESC`,
      [userId, userId, userId, userId]
    );

    return res.json(rows);
  } catch (err) {
    console.error('Matches error:', err);
    return res.status(500).json({ message: 'Serverfout bij matches ophalen.' });
  }
});

// ====== Chat ======

// GET /messages?matchId=123&userId=ME
app.get('/messages', async (req, res) => {
  try {
    const { matchId, userId } = req.query;
    if (!matchId || !userId) {
      return res.status(400).json({ message: 'matchId en userId zijn vereist.' });
    }

    const allowed = await userInMatch(matchId, userId);
    if (!allowed) return res.status(403).json({ message: 'Geen toegang tot deze match.' });

    const rows = await db.getQuery(
      'SELECT id, sender_id, content, sent_at FROM messages WHERE match_id = ? ORDER BY sent_at ASC',
      [matchId]
    );
    return res.json(rows);
  } catch (err) {
    console.error('Messages GET error:', err);
    return res.status(500).json({ message: 'Serverfout bij berichten ophalen.' });
  }
});

// POST /messages  { matchId, senderId, content }
app.post('/messages', async (req, res) => {
  try {
    const { matchId, senderId, content } = req.body;
    if (!matchId || !senderId || !content) {
      return res.status(400).json({ message: 'matchId, senderId en content zijn vereist.' });
    }

    const allowed = await userInMatch(matchId, senderId);
    if (!allowed) return res.status(403).json({ message: 'Geen toegang tot deze match.' });

    const result = await db.getQuery(
      'INSERT INTO messages (match_id, sender_id, content) VALUES (?, ?, ?)',
      [matchId, senderId, content]
    );

    return res.status(201).json({ message: 'Bericht verstuurd.', messageId: result.insertId });
  } catch (err) {
    console.error('Messages POST error:', err);
    return res.status(500).json({ message: 'Serverfout bij bericht verzenden.' });
  }
});

// ====== Health ======
app.get('/', (_req, res) => {
  res.send('Heart API running');
});

// ====== Start server ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Heart server running on port ${PORT}`);
});

app.get('/admin/users', async (req, res) => {
  try {
    const rows = await db.getQuery(
      `SELECT 
         u.id, u.email, u.username, u.bio, u.gender,
         DATE_FORMAT(u.birthdate, '%Y-%m-%d') AS birthdate,
         u.location,
         u.verified, u.banned,
         (SELECT photo_url FROM user_photos p WHERE p.user_id = u.id LIMIT 1) AS photo
       FROM users u
       ORDER BY u.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error('Admin GET users error:', err);
    res.status(500).json({ message: 'Serverfout bij ophalen gebruikers.' });
  }
});

app.post('/admin/verify', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: 'userId is vereist.' });

    await db.getQuery('UPDATE users SET verified = TRUE WHERE id = ?', [userId]);
    res.json({ message: 'Gebruiker geverifieerd.' });
  } catch (err) {
    console.error('Admin verify error:', err);
    res.status(500).json({ message: 'Serverfout bij verifiëren gebruiker.' });
  }
});

app.post('/admin/ban', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: 'userId is vereist.' });

    await db.getQuery('UPDATE users SET banned = TRUE WHERE id = ?', [userId]);
    res.json({ message: 'Gebruiker geband.' });
  } catch (err) {
    console.error('Admin ban error:', err);
    res.status(500).json({ message: 'Serverfout bij bannen gebruiker.' });
  }
});

app.delete('/admin/user/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    if (!userId) return res.status(400).json({ message: 'userId ontbreekt.' });

    // Verwijder foto's
    await db.getQuery('DELETE FROM user_photos WHERE user_id = ?', [userId]);

    // Verwijder swipes, matches en berichten
    await db.getQuery('DELETE FROM swipes WHERE swiper_id = ? OR target_id = ?', [userId, userId]);
    await db.getQuery('DELETE FROM messages WHERE sender_id = ?', [userId]);
    await db.getQuery('DELETE FROM matches WHERE user1_id = ? OR user2_id = ?', [userId, userId]);

    // Verwijder user zelf
    await db.getQuery('DELETE FROM users WHERE id = ?', [userId]);

    res.json({ message: 'Gebruiker verwijderd.' });
  } catch (err) {
    console.error('Admin delete user error:', err);
    res.status(500).json({ message: 'Serverfout bij verwijderen gebruiker.' });
  }
});

