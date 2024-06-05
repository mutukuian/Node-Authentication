const crypto = require('crypto');
const bcrypt = require("bcryptjs");
const express = require('express');
const app = express();
const mongoose = require("mongoose");
const cors = require("cors");
const PartnersModel = require('./models/Partners');

// Generate a random encryption key
const encryptionKey = crypto.randomBytes(32); // Generate a 32-byte encryption key

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
  const saltRounds = 10; // Adjust saltRounds as needed
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
      res.status(200).json("Successfully Login");
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

// Server Up
app.listen(3001, () => {
  console.log("Server is running on port 3001");
});
