const jwt = require('jsonwebtoken');
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require("bcryptjs");
const express = require('express');
const app = express();
const mongoose = require("mongoose");
const cors = require("cors");
const PartnersModel = require('./models/Partners');



// Generate a random encryption key
const encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY,'hex'); // Generate a 32-byte encryption key
if (encryptionKey.length !== 32) {
  throw new Error('Encryption key must be 32 bytes (64 hex characters)');
}
//console.log(encryptionKey)
const iv = crypto.randomBytes(16);
//console.log(iv) // Generate a 16-byte IV

function generateSecureString(length) {
  return crypto.randomBytes(length).toString('hex');
}

const secureString = process.env.SECURE_STRING; // Generate a 32-character (256-bit) secure string 
//console.log(secureString);

// Middleware
app.use(express.json());
app.use(cors());

// Database connection
const database = () => {
  const connectionParams = {};
  try {
    mongoose.connect(
      process.env.MONGO_URI,
      connectionParams
    );
    console.log("Database connected successfully");
  } catch (error) {
    console.log(error);
    console.log("Database connection failed");
    process.exit(1); // Exit process with failure
  }
};


database();

// Password hashing function
const hashPassword = async (password) => {
  const saltRounds = 10;
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  } catch (err) {
    console.error(err);
    throw new Error("Error hashing password");
  }
};

// Encryption function
function encryptData(data) {
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`; // Return IV along with encrypted data
}

// Decryption function
function decryptData(encryptedData) {
  try {
    const [ivHex, encrypted] = encryptedData.split(':');
    const ivBuffer = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, ivBuffer);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Error decrypting data');
  }
}

// APIs
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await PartnersModel.findOne({ email: email });

    if (!user) {
      return res.status(401).json("User does not exist");
    }

    // Compare entered password with decrypted password
    const decryptedPassword = decryptData(user.password); // Decrypt stored password
    const isMatch = await bcrypt.compare(password, decryptedPassword);

    if (isMatch) {
      // Generate JWT token
      const token = jwt.sign({ userId: user._id }, secureString, { expiresIn: '30s' });
      res.status(200).json({ status:"Success", message: "Login successfully",token });
    } else {
      res.status(401).json("Incorrect password");
    }

  } catch (err) {
    console.error(err);
    res.status(500).json("Server error");
  }
});

app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;

  try {
    // Hash password before saving
    const hashedPassword = await hashPassword(password);

    // Encrypt password before saving to database
    const encryptedPassword = encryptData(hashedPassword);

    // Create new user with encrypted password
    const newPartner = new PartnersModel({
      email,
      password: encryptedPassword,
      name
    });

    const userData = await newPartner.save();
    res.status(200).json({ status:"Success",message: "Registration successful" ,userData });

  } catch (err) {
    console.error(err);
    res.status(409).json("User already exists");
  }
});

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
  res.status(200).json("Protected route accessed");
});

// Middleware function to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json("Unauthorized: No token provided");
  }

  jwt.verify(token, secureString, (err, decoded) => {
    if (err) {
      return res.status(401).json("Unauthorized: Invalid token");
    }

    req.userId = decoded.userId;
    next();
  });
}

// Middleware to check token expiration
function checkTokenExpiration(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json("Unauthorized: No token provided");
  }

  jwt.verify(token, secureString, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        // Token expired, provide user-friendly message
        return res.status(401).json("Token expired. Please log in again to obtain a new token.");
      } else {
        // Other token verification errors
        return res.status(401).json("Unauthorized: Invalid token");
      }
    }

    req.userId = decoded.userId;
    next();
  });
}


// Server Up
app.listen(3001, () => {
  console.log("Server is running on port 3001");
});
