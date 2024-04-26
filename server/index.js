const express = require('express')
const app = express()
const mongoose = require("mongoose")
const cors = require("cors")
const PartnersModel = require('./models/Partners')

app.use(express.json())
app.use(cors())

//Database connection
const database = (module.exports = ()=>{
    const connectionParams ={
        useNewUrlParser:true,
        useUnifiedTopology:true
    };
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

//APIS

app.post('/login',(req,res) =>{
    const {email,password} = req.body;
    PartnersModel.findOne({email:email})
    .then(user =>{
        if(user){
            if(user.password === password){
                res.json("Success")
            }else{
                res.json("The password is incorrect")
            }
        }else{
            res.json("User does not exist")
        }
    })
});

app.post('/register',(req,res)=>{
    PartnersModel.create(req.body)
    .then(partners => res.json(partners))
    .catch(err => res.status(400).json(err))
});


//Server Up
app.listen(3001,()=>{
    console.log("Server is running on port 3001");
});