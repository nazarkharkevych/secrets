require('dotenv').config()

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const mongoose = require('mongoose');
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');
const port = process.env.PORT || 3000;

const app = express();
app.use(cookieParser());
app.use(session({ secret: 'some secrets', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

//MONGOOSE Schemas

main().catch(err => console.log(err));

async function main() {
  await mongoose.connect(process.env.MONGO_DB, { useNewUrlParser: true, useUnifiedTopology: true});
  }

const secretSchema = new mongoose.Schema({
  secret: String
});

const Secret = mongoose.model("Secret", secretSchema);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: [secretSchema]
  });

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

//Passport initialization, adding Google and Facebook strategies

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

passport.use(new FacebookStrategy({
  clientID: process.env.APP_ID,
  clientSecret: process.env.APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

//ROUTES

app.get("/", (req, res) => {
  res.render("home")
});

//Only authorized users can submit a secret 

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit")
  } else {
    res.redirect("/login")
  }
});

app.post("/submit", async (req, res) => {
  try {
  const submittedSecret = req.body.secret;
  const newSecret = new Secret ({secret: submittedSecret});
  Secret.find({secret: submittedSecret}, async function (err, foundSecret) {
      if (err) {
        console.log(err);
      } else {
        if (foundSecret.length === 0) {
          await newSecret.save();
          res.redirect("/secrets");
        } else {
          res.redirect("/secrets");
        }
      }
    });
} catch(e) {
  console.log(`Cath error: ${e}`);
}
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      Secret.find({}, async (err, foundSecrets) => {
        if (err) {
          console.log(err);
        } else {
          if (foundSecrets) {
            res.render("secrets", {usersWithSecrets: foundSecrets})
          }
        }
      });
    } catch(e) {
      console.log(e);
    }
  } else {
    res.redirect("/login")
  }

  });

  //OAuth authorization

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
passport.authenticate('facebook', { failureRedirect: '/login' }),
function(req, res) {
  res.redirect('/secrets');
});

app.get('/auth/google',
   passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
  res.redirect('/secrets');
});

//Login and registration

app.get("/login", (req, res) => {
    res.render("login")
});
    
app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login', failureMessage: true }), (req, res) => {
    res.redirect('/secrets');
  });

app.get("/register", (req, res) => {
    res.render("register")    
});
    
app.post("/register", async (req, res) => {
    try {
           User.register({ username: req.body.username }, req.body.password, function (err, userReg) {
             if (err) {
               console.log(`${err}`);
               res.redirect("/login");
             } else {
              passport.authenticate('local')(req, res, function () {
                res.redirect('/secrets');
              });
             }
           });

    } catch (e) {
        console.log("Catch error: " + e)
    }
});

//Only authorized users can delete a secret

app.post("/delete", async (req, res) => {

    const secretToDelete = req.body.checkbox
  try {
    Secret.findByIdAndDelete({_id: secretToDelete}, function(err, doc){
      if (err) {
        console.log(err)
      } else {
        res.redirect("/secrets")
      }
    });
  } catch (e) {
    console.log(e);
  }
  
});

app.get("/logout", (req, res) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
})


app.listen(port, function() {
  console.log(`Server started on port ${port}`);
});