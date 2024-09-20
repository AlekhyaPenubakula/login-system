const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT1 = 3003;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to the SQLite database:', err.message);
        process.exit(1); // Exit the application if the database connection fails
    } else {
        console.log('Connected to the SQLite database.');
    }
});

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    login_count INTEGER DEFAULT 0
)`, (err) => {
    if (err) {
        console.error('Error creating users table:', err.message);
    } else {
        console.log('Users table created or already exists.');
    }
});

app.post('/register', async (req, res) => {
    const { name, email, password, repassword } = req.body;

    if (password !== repassword) {
        return res.send('Passwords do not match');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, [name, email, hashedPassword], function (err) {
            if (err) {
                console.error('Error inserting user into database:', err.message);
                return res.send('Email already registered');
            }
            res.redirect('/login.html');
        });
    } catch (error) {
        console.error('Error hashing password:', error.message);
        res.send('Server error');
    }
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) {
            console.error('Error fetching user from database:', err.message);
            return res.send('User not found');
        }
        if (!user) {
            return res.send('User not found');
        }

        try {
            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.send('Incorrect password');
            }

            db.run(`UPDATE users SET login_count = login_count + 1 WHERE id = ?`, [user.id], (err) => {
                if (err) {
                    console.error('Error updating login count:', err.message);
                }
            });

            res.redirect('/ebook-buttons');
        } catch (error) {
            console.error('Error comparing passwords:', error.message);
            res.send('Server error');
        }
    });
});

app.get('/ebook-buttons', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'ebook-buttons.html'));
});

app.listen(PORT1, () => {
    console.log(`User registration and login server is running on port ${PORT1}`);
});
