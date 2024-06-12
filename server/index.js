const jwt = require('jsonwebtoken');
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const express = require('express');
const fs = require('fs');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const PartnersModel = require('./models/Partners');

// Load RSA keys
const publicKey = fs.readFileSync('public_key.pem', 'utf8');
const privateKey = fs.readFileSync('private_key.pem', 'utf8');
const passphrase = process.env.RSA_PASSPHRASE;

// Generate a random encryption key
const encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
if (encryptionKey.length !== 32) {
  throw new Error('Encryption key must be 32 bytes (64 hex characters)');
}

const secureString = process.env.SECURE_STRING;

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
    console.log('Database connected successfully');
  } catch (error) {
    console.log(error);
    console.log('Database connection failed');
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
    throw new Error('Error hashing password');
  }
};

// RSA encryption function
function encryptData(data) {
  const buffer = Buffer.from(data, 'utf8');
  const encrypted = crypto.publicEncrypt(publicKey, buffer);
  return encrypted.toString('hex');
}

// RSA decryption function
function decryptData(encryptedData) {
  try {
    const buffer = Buffer.from(encryptedData, 'hex');
    const decrypted = crypto.privateDecrypt({
      key: privateKey,
      passphrase: passphrase,
    }, buffer);
    return decrypted.toString('utf8');
  } catch (error) {
    console.error('Decryption error:', error);
    console.error('Encrypted data:', encryptedData);
    throw new Error('Error decrypting data');
  }
}

// Login API
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // Validate email format
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ error: 'Valid email address is required' });
  }

  // Check if email or password is missing
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Find user by email
    const user = await PartnersModel.findOne({ email: email });

    if (!user) {
      return res.status(404).json({ error: 'Email not found' });
    }

    // Decrypt stored password
    const decryptedPassword = decryptData(user.password);
    const isMatch = await bcrypt.compare(password, decryptedPassword);

    if (isMatch) {
      // Generate JWT token
      const token = jwt.sign({ userId: user._id, name: user.name }, secureString, { expiresIn: '1h' });
      res.status(200).json({ status: 'Success', message: 'Login successfully', name: user.name, token });
    } else {
      res.status(401).json('Incorrect password');
    }

  } catch (err) {
    console.error(err);
    res.status(500).json('Server error');
  }
});

// Register API
app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // Validate email format
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ error: 'Valid email address is required' });
  }

  // Check if email, password, or name is missing
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Email, password, and name are required' });
  }

  // Validate password strength
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}$/;

  if (!password || !passwordRegex.test(password)) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters long and include at least one lowercase letter, one uppercase letter, one numeric digit, and one special character'
    });
  }

  try {

    // Check if email already exists
    const existingUser = await PartnersModel.findOne({ email: email });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password before saving
    const hashedPassword = await hashPassword(password);

    // Encrypt password before saving to database
    const encryptedPassword = encryptData(hashedPassword);

    // Create new user with encrypted password
    const newPartner = new PartnersModel({
      email: email,
      password: encryptedPassword,
      name: name
    });

    const userData = await newPartner.save();
    const { password: userPassword, ...userWithoutPassword } = userData.toObject();
    res.status(200).json({ status: 'Success', message: 'Registration successful', userData: userWithoutPassword });

  } catch (err) {
    console.error(err);
    res.status(409).json('User already exists');
  }
});

// Endpoint to get all users (protected route)
app.get('/users', verifyToken, async (req, res) => {
  try {
    const users = await PartnersModel.find({}, '-password');
    res.status(200).json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json('Server error');
  }
});

// In your Express server file

app.get('/me', verifyToken, async (req, res) => {
  try {
      const user = await PartnersModel.findById(req.userId).select('-password');
      if (!user) {
          return res.status(404).json({ error: 'User not found' });
      }
      res.status(200).json(user);
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
  }
});


// Protected route example
app.get('/protected', verifyToken, (req, res) => {
  res.status(200).json('Protected route accessed');
});

// Refresh Token Endpoint
app.post('/refresh-token', (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    return res.status(401).json('Refresh token is required');
  }

  jwt.verify(refreshToken, secureString, (err, decoded) => {
    if (err) {
      return res.status(401).json('Invalid refresh token');
    }

    const accessToken = jwt.sign({ userId: decoded.userId }, secureString, { expiresIn: '1h' });
    res.status(200).json({ accessToken });
  });
});

// Middleware function to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json('Unauthorized: No token provided');
  }

  var tokenParts = token.split(' ')

  var accessToken = tokenParts[1]

  console.log("accessToken:" + accessToken)
  

  jwt.verify(accessToken, secureString, (err, decoded) => {
    if (err) {
      console.log(err)
      return res.status(401).json('Unauthorized: Invalid token');
    }

    req.userId = decoded.userId;
    next();
  });
}

// Middleware to check token expiration
function checkTokenExpiration(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json('Unauthorized: No token provided');
  }

  jwt.verify(token, secureString, (err) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json('Token expired. Please log in again to obtain a new token.');
      } else {
        return res.status(401).json('Unauthorized: Invalid token');
      }
    }

    next();
  });
}

// Server Up
app.listen(3001, () => {
  console.log('Server is running on port 3001');
});
