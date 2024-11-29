import express from "express";
import session from "express-session";
import passport from "passport";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import mysql from "mysql";
import cors from "cors";
import dotenv from "dotenv"; // Load environment variables

dotenv.config(); // Load .env file variables

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());

app.use(cors({
  origin: 'http://localhost:8080', // Remplace par l'URL du frontend
  credentials: true,
}));



// Session management
app.use(session({
  secret: 'your-secret-key', // Replace with a strong secret key
  resave: false,
  saveUninitialized: true,
  cookie: {    secure: false, // Devrait être à `true` en production (si vous utilisez HTTPS)
    httpOnly: true, // Empêche l'accès au cookie via JavaScript
    maxAge: 3600000,  } // Set to true if using HTTPS
}));

// MySQL database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Change if necessary
  password: "", // Add database password if applicable
  database: "goal_getter_db", 
});

db.connect((err) => {
  if (err) {
    console.error("Erreur de connexion à la base de données:", err);
    return;
  }
  console.log("Connecté à la base de données MySQL");
});

// Sign-up route
app.post("/signup", async (req, res) => {
  const { name, surname, email, password } = req.body;

  if (!name || !surname || !email || !password) {
    return res.status(400).json({ message: "Veuillez remplir tous les champs !" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO users (name, surname, email, password) VALUES (?, ?, ?, ?)";
    db.query(sql, [name, surname, email, hashedPassword], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "Erreur lors de l'enregistrement de l'utilisateur !" });
      }
      res.status(201).json({ message: "Utilisateur enregistré avec succès !" });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Une erreur s'est produite pendant l'enregistrement !" });
  }
});

// Login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Veuillez fournir un email et un mot de passe !" });
  }

  const sql = "SELECT * FROM users WHERE email = ?"; 
  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Erreur lors de la connexion !" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Email incorrect ou utilisateur inexistant !" });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Mot de passe incorrect !" });
    }

    // Store user info in session
    req.session.user = {
      id: user.id,
      name: user.name,
      surname: user.surname,
      email: user.email
    };

    res.status(200).json({ message: `Bienvenue ${user.name} ${user.surname}!` });
  });
});

// Middleware to protect private routes
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next(); // User is authenticated
  }
  res.status(401).json({ message: "Accès non autorisé. Veuillez vous connecter !" });
}

// Private route
app.get("/private", isAuthenticated, (req, res) => {
  res.json({
    message: `Bienvenue dans l'espace privé, ${req.session.user.name} ${req.session.user.surname}!`,
    user: req.session.user
  });
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Erreur lors de la déconnexion." });
    }
    res.clearCookie('connect.sid'); // Clear session cookie
    res.json({ message: "Déconnecté avec succès !" });
  });
});

// Start server
app.listen(port, () => {
  console.log(`Serveur démarré sur http://localhost:${port}`);
});
