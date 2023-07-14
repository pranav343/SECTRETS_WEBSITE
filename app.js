require('dotenv').config();
const express =require("express");
const bodyParser =require('body-parser');
const ejs = require('ejs');
const mongoose =require('mongoose');
//CONST FOR OAUTH GOOGLE 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
//facebook
const FacebookStrategy = require('passport-facebook').Strategy;
//Const added for PASSPORT
const session =require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');

const findOrCreate = require('mongoose-findorcreate');

// const bcrypt = require('bcrypt');  //BCRYPT HASHING ENCRYPTION
// const saltRounds = 10;

// const md5 = require('md5');              //MD5 hashing require
// const encrypt =require('mongoose-encryption');     //MONGOOSE ENCRYPTION

const app = express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: "Our little secret.",
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

//mongoDB connection
mongoose.connect("mongodb://127.0.0.1:27017/userDB")
.then(()=>{console.log("mongoDb connected succesfully")})
.catch((err)=>{console.log(err)});

//SCHEMAS
const userSchema= new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    secret:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//ENCRYPTION OF PASSWORD (by mongoose-encryption)

// const secret = process.env.SECRET;
// userSchema.plugin(encrypt,{secret : secret , encryptedFields:["password"] }); //this will only encrypt the password not the whole data of user.

//MODELS
const User = mongoose.model("User",userSchema)

passport.use(User.createStrategy());
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
   
  passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
      return cb(null, user);
    });
  });

//THE BELOW CODE IS FOR OAUTH GOOGLE AND IT SHOULD BE ALWAYS UNDER THE ABOVE 3 LINE CODE WHERE WE HAVE SERIALIZE AND DESERIALIZE THE PASSPORT
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
   
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//GET REQ
app.get("/", function(req,res)
{
    res.render("home");

});

//authentication 
//google
app.get("/auth/google",
passport.authenticate('google', { scope: ["profile"] })
);
//facebook
app.get('/auth/facebook',
  passport.authenticate('facebook'));
//callback when auth is done
//GOOGLE
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });
  //FACEBOOK
  app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secret.
    res.redirect('/secrets');
  });



app.get("/login", function(req,res)
{
    res.render("login");

});

app.get("/register", function(req,res)
{
    res.render("register");

});
app.get("/secrets",function(req,res)
{
    if(req.isAuthenticated) //this will check that if the user is authenticated or not
    {
         //if user is authenticated then it will open secrets
       
        User.find({"secret":{$ne:null}}) //this will find the users whose secret field is not null
        .then((userFound)=>{
            res.render("secrets" ,{userwithSecrets:userFound});
        })
        .catch((err)=>{console.log(err)})
    }
    else{
        res.redirect("/login"); //if user is not authenticated it will send him to login page
    }
});
app.get("/logout",function(req,res)
{
    req.logout((err)=>{
        if(err)
        {
            console.log(err);
        }
        else{
            res.redirect("/");
        }
    })
   
});
app.get("/submit", function(req,res)
{
    if(req.isAuthenticated) 
    {
        res.render("submit"); 
    }
    else{
        res.redirect("/login"); 
    }

})

//POST REQ
app.post("/register",function(req,res)
{
    User.register({username:req.body.username} ,req.body.password , function(err, user){
        if(err)
        {
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function()
            {
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/login", function(req,res)
{
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });
    //LOGIN USING PASSPORT
    req.login(user,function(err){
        if(err)
        {
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function()
            {
                res.redirect("/secrets");
            })
        }
    })

})
app.post("/submit",function(req,res)
{
    const submittedSecret=req.body.secret;
    const usergivenId=req.user.id;
    console.log(submittedSecret);
    console.log(usergivenId);
    User.findById(usergivenId)
    .then((founduser)=>{
        founduser.secret=submittedSecret;
        founduser.save()
        .then(()=>{
            res.redirect("/secrets");
        }) 
    })
    .catch((err)=>{
        console.log("the error is "+err);
    })
});

app.listen(process.env.PORT|| 3000 , function()
{
    console.log("server started at port 30000");
});





///OLD CODE BEFORE USING PASSPORT , FOR APP.POST AND APP.GET

//-------------------------------------------
// app.post("/register",function(req,res)
// {
//     //BCRYPT HASHING
//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//         const newUser = new User({
//             email:req.body.username,
//             password:hash
//         });
//         newUser.save()
//         .then(()=>{
//             res.render("secrets");
//         })
//         .catch((err)=>{console.log(err)});
//     });
//     });

    
// app.post("/login",function(req,res)
// {
//     const emailID=req.body.username;
//     const password=req.body.password;
//     // const password=md5(req.body.password);    //MD5 code
    

//     User.findOne({email:emailID})
//     .then((userInfo)=>{
//         bcrypt.compare(password, userInfo.password, function(err, result) {
//             if(result==true)
//             {
//                 res.render("secrets");
//             }
//             else{
//                 console.log(err);
//                 console.log("wrong password");
//             }
//         });
        
//     })
//     .catch((err)=>{console.log(err)});
// });
