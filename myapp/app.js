const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const mongoDBStore=require('connect-mongodb-session')(session)
const csrf=require('csurf')
const flash=require('connect-flash')

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");

const errorController = require("./controllers/error");
// const mongoConnect=require("./util/database").mongoConnect;
const User = require("./models/user");
const MONGODB_URI="mongodb+srv://sarita:sarita9643@cluster0.gbywgfa.mongodb.net/shop";

const app = express();
const store=new mongoDBStore({
    uri:MONGODB_URI,
    collection:'sessions'
})
const csrfProtection=csrf()
app.use(flash())


app.set("view engine", "ejs");
app.set("views", "views");

const adminRoutes = require("./routes/admin");
const shopRoutes = require("./routes/shop");
const authRoutes = require("./routes/auth");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({ secret: "my secret", resave: false, saveUninitialized: false,store:store })
);
app.use(csrfProtection)
app.use((req,res,next)=>{
  if(!req.session.user)
  {
   return next()
  }
  User.findById(req.session.user._id)
    .then((user) => {
      if(!user)
      {
        return next()
      }
      req.user = user;
      next();
    })
 .catch((err) => {
      throw new Error(err)
    });
  })
  app.use((req,res,next)=>{
    res.locals.isAuthenticated=req.session.isLoggedIn;  
    res.locals.csrfToken=req.csrfToken()
    next() 

  })
  

app.use("/admin", adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.get('/500',errorController.get500)
app.use(errorController.get404);

// mongoConnect(client=>{

//     app.listen(5000)
// })

mongoose
  .connect(
    MONGODB_URI
  )
  .then((result) => {
     app.listen(5000);
    console.log("Database Connected");
  })
  .catch((err) => {
    console.log(err);
  });
