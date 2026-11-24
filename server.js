const express = require('express');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = 3000;
const MONGO_URI = 'mongodb://192.168.78.129:27017';

app.use(express.json());

let usersCollection;

MongoClient.connect(MONGO_URI)
  .then((client) => {
    const db = client.db('nettrack');
    usersCollection = db.collection('users');
    console.log('Connected to MongoDB on VM 3');
  })
  .catch((err) => console.error('MongoDB connection error:', err));

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, key] = storedHash.split(':');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(key, 'hex'), derivedKey);
}

app.post('/api/register', async (req, res) => {
  const fullname = String(req.body.fullname || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!fullname || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const existing = await usersCollection.findOne({ email });
  if (existing) {
    return res.status(409).json({ error: 'Email already registered.' });
  }

  const passwordHash = hashPassword(password);
  await usersCollection.insertOne({
    fullname,
    email,
    passwordHash,
    createdAt: new Date(),
  });

  res.status(201).json({ message: 'Account created successfully.' });
});

app.post('/api/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const user = await usersCollection.findOne({ email });
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  res.json({ message: 'Login successful.', user: user.fullname });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Back-End listening on port ${PORT}`);
});
