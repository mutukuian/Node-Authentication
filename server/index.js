const bcrypt = require("bcryptjs");
const express = require('express')
const app = express()
const mongoose = require("mongoose")
const cors = require("cors")
const PartnersModel = require('./models/Partners')

app.use(express.json())
app.use(cors())

// Database connection
const database = (module.exports = () => {
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
});

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

// APIS

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await PartnersModel.findOne({ email: email });

    if (!user) {
      return res.json("User does not exist");
    }

    // Compare entered password with hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      res.json("Successfully Login");
    } else {
      res.json("Incorrect password");
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

    // Create new user with hashed password
    const newPartner = new PartnersModel({
      email,
      password: hashedPassword,
      name
    });

    const savedPartner = await newPartner.save();
    res.json(savedPartner);

  } catch (err) {
    console.error(err);
    res.status(400).json("User already exists");
  }
});

// Server Up
app.listen(3001, () => {
  console.log("Server is running on port 3001");
});
