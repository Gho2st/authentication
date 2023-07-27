//jshint esversion:6
require('dotenv').config();
const express = require("express")
const bodyParser = require("body-parser")
const ejs = require("ejs")
const mongoose = require("mongoose")
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')


const app = express();

app.use(express.static('public'))

app.set("view engine", 'ejs')

app.use(bodyParser.urlencoded({
    extended:true
}));

app.use(session({
    secret: 'our little secret.',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
  }))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/userDB', {useNewUrlParser: true})


const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

userSchema.plugin(passportLocalMongoose)


const User = new mongoose.model("User", userSchema)

passport.serializeUser(User.serializeUser())
passport.deserializeUser(User.deserializeUser())

app.get("/", function(req, res){
    res.render('home');
})

app.get("/login", function(req, res){
    res.render('login');
})

app.get("/register", function(req, res){
    res.render('register');
})

app.get('/secrets', function(req, res){
    if (req.isAuthenticated()){
        res.render('secrets')
    } else {
        res.redirect('/login')
    }
});

app.get("/logout", function(req, res){
    res.render('home');
})

app.post("/register", function(req, res){

    User.register({username:req.body.username}, req.body.password, function(err, user){
        if (err){
            console.log(err)
            res.redirect("/register")
        } else {
            passport.authenticate('local')(req, res, function(){
                res.redirect('/secrets')
            })
        }
    })
  
 
});

app.post('/login', function(req, res){
    
});
app.listen(3000, function(){
    console.log("Server started on port 3000.")
})