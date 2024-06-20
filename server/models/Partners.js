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
  },
  createdAt:{
    type:String,
    default:Date.now
  },
  status:{
    type:String,
    enum:['active','inactive'],
    default:'active'
  },
});

// Create the model
const PartnersModel = mongoose.model("Partner", PartnersSchema);

module.exports = PartnersModel;
