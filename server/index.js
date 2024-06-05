const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require("bcryptjs");
const express = require('express');
const app = express();
const mongoose = require("mongoose");
const cors = require("cors");
const PartnersModel = require('./models/Partners');

// Generate a random encryption key
const encryptionKey = crypto.randomBytes(32); // Generate a 32-byte encryption key

function generateSecureString(length) {
  return crypto.randomBytes(length).toString('hex');
}

const secureString = generateSecureString(32); // Generate a 32-character (256-bit) secure string
console.log(secureString);

//middleware
app.use(express.json());
app.use(cors());

// Database connection
const database = () => {
  const connectionParams = {};
  try {
    mongoose.connect(
      'mongodb+srv://mutukui940:gXa1lZndASK9vim8@cluster0.uh75qkt.mongodb.net/JavaSelfDriveAuth',
      connectionParams
    );
    console.log("Database connected successfully");
  } catch (error) {
    console.log(error);
    console.log("Database connection failed");
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
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, Buffer.alloc(16));
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Decryption function
function decryptData(encryptedData) {
  try {
      const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, Buffer.alloc(16));
      let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
  } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Error decrypting data');
  }
}

// APIS

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
      //generate jwt token
      const token = jwt.sign({userId: user._id},secureString,{expiresIn:'30s'})
      res.status(200).json({token});
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

    const savedPartner = await newPartner.save();
    res.status(200).json(savedPartner);

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

  jwt.verify(token, 'your_secret_key', (err, decoded) => {
    if (err) {
      return res.status(401).json("Unauthorized: Invalid token");
    }

    req.userId = decoded.userId;
    next();
  });
}

// Server Up
app.listen(3001, () => {
  console.log("Server is running on port 3001");
});
