//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/userDB', {useNewUrlParser: true});


const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
async function(accessToken, refreshToken, profile, cb) {
  console.log(profile);

  try {
    const user = await User.findOne({ googleId: profile.id }).exec();
    if (user) {
      return cb(null, user);
    } else {
      const newUser = new User({
        googleId: profile.id,
        username: profile.displayName // Assuming the display name is the same as the username for simplicity.
      });
      const savedUser = await newUser.save();
      return cb(null, savedUser);
    }
  } catch (err) {
    return cb(err, null);
  }
}
));

app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", async function(req, res) {
  try {
    const foundUsers = await User.find({ "secret": { $ne: null } }).exec();
    if (foundUsers) {
      res.render("secrets", { usersWithSecrets: foundUsers });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred while fetching secrets.");
  }
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async function(req, res) {
  const submittedSecret = req.body.secret;

  try {
    const foundUser = await User.findById(req.user.id).exec();
    if (foundUser) {
      foundUser.secret = submittedSecret;
      await foundUser.save();
      res.redirect("/secrets");
    }
  } catch (err) {
    console.log(err);
  }
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/register", async function(req, res) {
  try {
    const user = new User({ username: req.body.username });
    await User.register(user, req.body.password);
    passport.authenticate("local")(req, res, function() {
      res.redirect("/secrets");
    });
  } catch (err) {
    console.log(err);
    res.redirect("/register");
  }
});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, async function(err) {
    try {
      if (err) {
        console.log(err);
      } else {
        await passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    } catch (err) {
      console.log(err);
    }
  });
});


app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
