const bcrypt = require('bcrypt');
const express = require('express');
const path = require('path');
const mysql = require('mysql');
const cookieParser = require('cookie-parser');
const session = require('express-session');


  
const app = express();
const port = process.env.PORT || 3019;


app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const pool = mysql.createPool({
    connectionLimit: 10,
    host: process.env.JAWSDB_URL, // Provided by Heroku
    user: process.env.JAWSDB_USER,
    password: process.env.JAWSDB_PASSWORD,
    database: process.env.JAWSDB_DATABASE
});

// Check and create tables if they don't exist
const createUserTableQuery = `
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    api_calls_made INT DEFAULT 0,
    is_admin BOOLEAN DEFAULT FALSE
)`;
pool.query(createUserTableQuery, (error, results) => {
    if (error) throw error;
    console.log("User table checked/created.");
});

app.use(express.urlencoded({ extended: true }));

app.use(express.json());

// CORS and Content Security Policy middleware
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    } else {
        next();
    }
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'fallbackSecretKey',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true } // secure should be true in production with HTTPS
  }));

let fetch;
import('node-fetch').then(({ default: nodeFetch }) => {
  fetch = nodeFetch;
});


  
  // Middleware to verify if a user is logged in and an admin
  const verifyAdmin = (req, res, next) => {
    if (!req.session.userId || !req.session.isAdmin) {
      return res.status(403).send('Unauthorized');
    }
    next();
  };

// Middleware to verify session cookie
const verifySession = (req, res, next) => {
    const sessionId = req.cookies.sessionId;

    if (!sessionId) {
        return res.status(401).send('Access Denied: Session ID is not provided');
    }

    // Perform any necessary verification of the session ID
    // For example, you can query the database to validate the session

    // Assuming session validation is successful
    next();
};

// Routes
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', (req, res) => {
    const { email, password } = req.body;

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            res.status(500).send('Error hashing password');
            return;
        }

        const user = { email, password: hashedPassword };

        pool.query('INSERT INTO users SET ?', user, (err, result) => {
            if (err) {
                res.status(500).send('Error registering user');
                return;
            }
            console.log('User registered');
            res.redirect('/login');
        });
    });
});


app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).send('Error finding user');
    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) return res.status(500).send('Error comparing passwords');
        if (isMatch) {
          // Set session information
          req.session.userId = user.id;
          req.session.isAdmin = Boolean(user.is_admin); // Ensure boolean conversion
          res.redirect('/protected');
        } else {
          res.send('Incorrect password');
        }
      });
    } else {
      res.send('Email not registered');
    }
  });
});



app.post('/generate-quote', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) {
        return res.status(401).send('Unauthorized');
    }

    // Fetch the current number of API calls made by the user
    pool.query('SELECT api_calls_made FROM users WHERE id = ?', [userId], async (error, results) => {
        if (error || results.length === 0) {
            return res.status(500).send('Error fetching user data');
        }
        const { api_calls_made } = results[0];
        if (api_calls_made >= 20) {
            // Inform the client that the user has maxed out their free API calls
            return res.json({ message: "You have maxed out your free API calls.", continue: true });
        } else {
            try {
                const flaskResponse = await fetch('http://127.0.0.1:5000/generate-quote', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(req.body)
                });

                if (!flaskResponse.ok) {
                    throw new Error(`Flask server error: ${flaskResponse.statusText}`);
                }

                const data = await flaskResponse.json();
                // Update the API call count for the user
                pool.query('UPDATE users SET api_calls_made = api_calls_made + 1 WHERE id = ?', [userId]);
                res.json(data);
            } catch (error) {
                console.error('Error:', error);
                res.status(500).send('Error fetching quote.');
            }
        }
    });
});

app.get('/protected', verifySession, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'protected.html'));
});

app.get('/quote_generator', verifySession, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'quote_generator.html'));
});

app.get('/api/admin/usage', verifyAdmin, (req, res) => {
    pool.query('SELECT email, api_calls_made FROM users', (error, results) => {
        if (error) return res.status(500).send('Error fetching data');
        res.json(results);
    });
});

app.get('/api/usage', verifySession, (req, res) => {
    const userId = req.session.userId;
    pool.query('SELECT api_calls_made FROM users WHERE id = ?', [userId], (error, results) => {
        if (error) {
            return res.status(500).send('Error fetching API usage data');
        }
        if (results.length > 0) {
            const usage = results[0].api_calls_made;
            res.json({ apiCallsMade: usage });
        } else {
            res.status(404).send('User not found');
        }
    });
});


// Start server
app.listen(port, () => {
    console.log(`Server running on ${port}`);
});