const mongoose = require('mongoose')

const PartnersSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String
})

const PartnersModel =mongoose.model("JavaSelfDriveAuth",PartnersSchema)

module.exports = PartnersModel 