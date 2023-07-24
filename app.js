//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");
dotenv.config();

const app = express();

app.use(cookieParser());
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

//? MongoDB connection configeration
const mongoUri = process.env.MONGO_URI;
mongoose.connect(mongoUri);

const secretKey = process.env.SECRET;

// Secrets Scheea
const secretSchema = new mongoose.Schema({
  secret: String,
});

const Secret = new mongoose.model("Secret", secretSchema);

// user schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  tokens: [
    {
      token: {
        type: String,
        required: true,
      },
    },
  ],
  secret: {
    type: mongoose.Schema.Types.String,
    ref: "Secret",
  },
});

// Generating token
userSchema.methods.generateAuthToken = async function () {
  try {
    const token = jwt.sign({ _id: this._id.toString() }, secretKey);
    this.tokens = this.tokens.concat({ token: token });
    await this.save();
    return token;
  } catch (error) {
    console.log("There was an error");
  }
};

// Hashing the password
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  }
});

const User = new mongoose.model("User", userSchema);

// Authentication Middleware
const auth = async (req, res, next) => {
  try {
    const userToken = req.cookies.jwt;
    const verifyUser = jwt.verify(userToken, secretKey);
    const ID = verifyUser._id
    const foundUser = await User.findOne({ _id: ID });
  
    req.token = userToken;
    req.user = foundUser;

    next();
  } catch (error) {
    console.log(error);
  }
};

// Showing the ejs pages
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/submit", auth, (req, res) => {
  res.render("submit");
});


// Logout from a single device
app.get("/logout", auth, async (req, res) => {
  try {
    
    req.user.tokens = req.user.tokens.filter((currentElemnet) => {
      return currentElemnet.token !== req.token;
    })
    res.clearCookie("jwt");
    await req.user.save();
    res.render("home");

  } catch (error) {
    console.log(error);
  }
});

// Logout from all devices
app.get("/logoutall", auth, async (req, res) => {
  try {

    req.user.tokens = []
    res.clearCookie("jwt")
    await req.user.save()
    res.render("home")

  } catch (error) {
    console.log(error);
  }
})

app.post("/submit", async (req, res) => {
  try {
    const secret = req.body.secret;
    const newSecret = new Secret({
      secret: secret,
    });

    const saveSecret = await newSecret.save();

    res.status(201).render("secrets");
  } catch (error) {
    console.log(error);
  }
});

// Signup logic
app.post("/register", async (req, res) => {
  try {
    const email = req.body.username;
    const password = req.body.password;

    const newUser = new User({
      email: email,
      password: password,
    });

    const token = await newUser.generateAuthToken();

    res.cookie("jwt", token, {
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      httpOnly: true,
    });

    const registerdUser = await newUser.save();

    res.status(201).render("secrets");
  } catch (error) {
    console.log(error);
  }
});

// Login logic
app.post("/login", async (req, res) => {
  try {
    const email = req.body.username;
    const password = req.body.password;

    const foundUser = await User.findOne({ email: email });

    const passwordMatch = await bcrypt.compare(password, foundUser.password);

    const token = await foundUser.generateAuthToken();

    res.cookie("jwt", token, {
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      httpOnly: true,
    });

    if (passwordMatch) {
      res.status(201).render("secrets");
    } else {
      console.log("Wrong Password");
    }
  } catch (error) {
    console.log(error);
  }
});

// App server
app.listen(3000, () => {
  console.log("Server started on http://localhost:3000");
});
