// Test User Authentication - Elaina 
// This is NOT perfect and NOT secure enough, needs HTTPS and further security measures.
// Need to implement short-lived tokens + refresh tokens.

/* DOWNLOAD THE FOLLOWING DEPENDENCIES IN THE TERMINAL
    "bcryptjs": "^3.0.3",
    "cookie-parser": "^1.4.7",
    "dotenv": "^17.3.1",
    "express": "^5.2.1",
    "express-rate-limit": "^8.3.1",
    "helmet": "^8.1.0",
    "jsonwebtoken": "^9.0.3"
*/

// Needed to grab the dotenv file where secret key is found
// Store it in .env for security reasons
// Make sure .env is included in .gitignore, makes it invisible on the github page.
require("dotenv").config();

// What we use to run the server.
const express = require('express');

// Creates & verifies login tokens.
const jwt = require('jsonwebtoken');

// Used to hash passwords securely.
const bcrypt = require('bcryptjs');

// Used to read users.json and write in it.
const fs = require('fs');

// Used for safe file paths.
const path = require('path');

// Adds necessary security headers to help prevent XSS attacks and more.
const helmet = require('helmet');

// Used to block spam login attempts and registers.
const rateLimit = require('express-rate-limit');

//Allows us to read cookies (req.cookies).
const cookieParser = require('cookie-parser');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minutes
  max: 10, // 10 Attempts
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many login attempts. Try later. '})
  }
})

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(helmet());

// Sets as the default page
app.get('/', (req,res)=>{
  res.sendFile(__dirname + '/public/register.html');
});

// Sets the attempt limiters.
app.use('/register', limiter);
app.use('/login', limiter);

const importantKey = process.env.JWT_SECRET;
if (!importantKey) {
  console.error("JWT_SECRET is missing from .env");
  process.exit(1);
}

function authenticateToken (req, res, next) {
  const token = req.cookies.token; 

  if (!token) return res.redirect('/login.html');

  jwt.verify(token, importantKey, (err, user) => {
    if (err) return res.redirect('/login.html');

    req.user = user;
    next();
  })
}

function getUsers () {
  try {
    const data = fs.readFileSync('users.json');
    return JSON.parse(data);
  }
  catch (err){
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

// Upon receiving a post request from register, run the following ->
app.post('/register', async (req, res) => {
  const { password } = req.body;
  const users = getUsers();
  const username = req.body.username.toLowerCase();

  if (!username?.trim() || !password?.trim()) return res.status(400).send('Username and password are required.');
  if (username.includes(' ')) return res.status(400).send('Username cannot contain spaces');

  const userExists = users.find(u => u.username === username);
  if (userExists) return res.status(400).send("User already exists.");

  if (password.trim().length < 6) return res.status(400).send('Password must be at least 6 characters.')

  const hashedPassword = await bcrypt.hash(password,10);
  users.push({username, password: hashedPassword});

  saveUsers(users);
  res.send('User registered!');
});

app.post('/login', async (req, res) => {
  const { password } = req.body;
  const username = req.body.username.toLowerCase();

  const users = getUsers();
  const user = users.find(u => u.username === username);

  if (!username?.trim() || !password?.trim()) return res.status(400).send('Username and password required.')

  if (!user) return res.status(401).send('Invalid credentials.');

  const valid = await bcrypt.compare(password, user.password)
  if (!valid) return res.status(401).send('Invalid credentials.');

  const token = jwt.sign(
    {username },
    importantKey,
    { expiresIn: '1h' }
  );

  res.cookie('token', token, {
    httpOnly: true,
    secure: false, // Should change to true in actual production, this is just a test
    sameSite: 'Strict',
    maxAge: 60 * 60 * 1000 // 1 Hour
  });

  res.send('Logged in!');
});

app.post('/logout', (req,res)=>{
  res.clearCookie('token', {
    httpOnly: true,
    secure: false,
    sameSite: 'Strict',
    path: '/'
  });

  res.sendStatus(200);
});

app.get(['/dashboard','/dashboard/'], authenticateToken, (req,res) => {
  res.sendFile(path.join(__dirname,'private','dashboard.html'));
});

app.get('/api/user', authenticateToken, (req, res) => {
  res.json({ username: req.user.username });
});

app.use(express.static('public'));

app.listen(3000,() => {
  console.log('Server running on port 3000');
}).on("error", (err) => {
  console.error("Server failed to start:", err);
});
