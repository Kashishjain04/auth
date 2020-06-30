//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate'); 

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: 'thisismekashishjain',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: "auto" }
  }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/usersDB', {useUnifiedTopology: true, useNewUrlParser: true});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    picture: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema); 

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());
 
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

//Google Strategy

passport.use(new GoogleStrategy({
     clientID: process.env.GOOGLE_ID,
     clientSecret: process.env.GOOGLE_SECRET,
     callbackURL: "http://localhost:3000/auth/google/secrets",
     userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb){
        console.log("picture:" + profile._json.picture);
        User.findOrCreate({googleId: profile.id, picture: profile._json.picture}, function(err, user){
            return cb(err, user);
        });
    }
 ));

//Facebook Strategy

passport.use(new FacebookStrategy({
    clientID: process.env.FB_ID,    
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// GET requests

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {scope: ["profile "] }));

app.get("/auth/facebook", passport.authenticate("facebook", {scope: ["profile "] }));

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
        //console.log(req.user);
        res.render("secrets", {secret: req.user.secret, picture: req.user.picture});
    } 
    else{
      res.redirect("/login");
    }
});

app.get("/auth/google/secrets", passport.authenticate("google", {failureRedirect: "/login"} ), function(req, res){
    res.redirect("/secrets");
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
    res.render("submit");
    } else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){    
    User.findById(req.user._id, function(err, foundUser){
        if(err){
            console.log(err);
        } else{
            foundUser.secret = req.body.secret;
            foundUser.save(function(){
                res.redirect("/secrets");
            });
        }
    })    
});

app.post("/register", function(req, res){
    var picture;
    if(req.body.picture){
        var picture = req.body.picture;
    } else{
        var picture = "https://cdn.business2community.com/wp-content/uploads/2017/08/blank-profile-picture-973460_640.png";
    }
    User.register({username: req.body.username, picture: picture}, req.body.password, function(err, user){        
        console.log(user);        
        if(err){
        console.log(err);
        res.redirect("/register");
        }        
        else{
            passport.authenticate("local")(req, res, function(){                
                res.redirect("/secrets");
            });
        }
    });
     
});

app.post("/login", function(req, res){
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    //login using passport's login method
    req.login(user, function(err){
        if(err){
            console.log(err);
        } else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

});

app.listen(3000, function(){
    console.log("Started on port: 3000");
})
