const mongoose = require('mongoose');

// Define the schema
const PartnersSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  }
});

// Create the model
const PartnersModel = mongoose.model("Partner", PartnersSchema);

module.exports = PartnersModel;
