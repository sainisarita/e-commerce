const crypto=require("crypto")
const bcrypt = require("bcryptjs");
const nodemailer=require('nodemailer')
const sendgridTransport=require('nodemailer-sendgrid-transport')
const {validationResult}=require('express-validator/check')
const User = require("../models/user");

let transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: '123sainisarita@gmail.com',
        pass: 'uklypvadzhtqedji'
    }
});

exports.getLogin = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
    oldInput:{
      email:''
    }
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
    oldInput:{
      email:"",
      password:"",
      confirmPassword:""
    },validationErrors:""
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors=validationResult(req);
 if(!errors.isEmpty()){
  console.log(errors.array())
  return res.status(422).render("auth/login", {
    path: "/login",
    pageTitle: "login",
    errorMessage: errors.array()[0].msg,
    oldInput:{
      email:email
    }
  })
 }
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return res.status(422).render("auth/login", {
          path: "/login",
          pageTitle: "login",
          errorMessage:  "Invalid email or password",
          oldInput:{
            email:email
          }
        })
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
            });
          }
        return res.status(422).render("auth/login", {
          path: "/login",
          pageTitle: "login",
          errorMessage:  "Invalid email or password",
          oldInput:{
            email:email
          }
        })
        })
        .catch((err) =>{
          const error=new Error(err)
          error.httpStatusCode=500;
          next(error);
        });
    })
    .catch((err) => {
      const error=new Error(err)
      error.httpStatusCode=500;
      next(error);
    });
};
// Handle signup form submission
exports.postSignup = (req, res, next) => {
const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
 const errors=validationResult(req);
 if(!errors.isEmpty()){
  console.log(errors.array())
  return res.status(422).render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: errors.array()[0].msg,
    oldInput:{email:email,password:password,confirmPassword:req.body.confirmPassword}
    ,validationErrors:errors.array()
  }) 
 }
   bcrypt
        .hash(password, 12)
        .then((hashedPassword) => {
          const user = new User({
            email: email,
            password: hashedPassword,
            cart: { items: [] },
          });
          return user.save();
        })
  
      
      .then((result) => {
          // Send a welcome email to the new user using nodemailer
          // let mailOptions = {
          //   from: '123sainisarita@gmail.com',
          //   to: email,
          //   subject: 'Signup Succeeded',
          //   html: '<p>You successfully signed up!</p>'
          // };
          // transporter.sendMail(mailOptions, (error, info) => {
          //   if (error) {
          //     console.log(error);
          //   } else {
          //     console.log('Email sent: ' + info.response);
          //   }
          // });
          res.redirect("/login");
        }).catch(err=>{
          const error=new Error(err)
          error.httpStatusCode=500;
          next(error);
        })
  
    }
    




exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};
exports.getReset=(req,res,next)=>{
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  } 
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message
  });
}
exports.postReset=(req,res,next)=>{
  crypto.randomBytes(32,(err,buffer)=>{
    if(err)
      {
        console.log(err)
        return res.redirect('/reset')
      }
      const token=buffer.toString('hex')
      User.findOne({email:req.body.email})
      .then(user=>{
        if(!user)
        {
          req.flash('error','No account with that email found.' )
          return res.redirect('/reset')
        }
        user.resetToken=token;
        user.resetTokenExpiration=Date.now()+ 3600000;
        return user.save();
      })
      .then(result=>{
        res.redirect('/')
        transporter.sendMail({
          from: '123sainisarita@gmail.com',
          to:  req.body.email,
          subject: 'Password reset',
          html: `
            <p> You requested a password reset</p>
            <p>Click this <a href="http://localhost:5000/reset/${token}">link</a> to set a new Password.</p>
          `
        });
        
      })
      .catch(err=>{
        const error=new Error(err)
        error.httpStatusCode=500;
        next(error);
      })
    })
}
exports.getNewPassword=(req,res,next)=>{
  const token=req.params.token;
  User.findOne({resetToken: token,resetTokenExpiration:{$gt: Date.now()}})
  .then(user=>{
    let message = req.flash("error");
    if (message.length > 0) {
      message = message[0];
    } else {
      message = null;
    }
    res.render("auth/new-password", {
      path: "/new-password",
      pageTitle: "New Password",
      errorMessage: message,
      userId: user._id.toString(),
      passwordToken: token,
    });
  }
    
  )
  .catch(err=>{
    const error=new Error(err)
    error.httpStatusCode=500;
    next(error);
  })
  
}
exports.postNewPassword  =(req,res,next)=>{
  const newPassword=req.body.password;
  const  userId=req.body.userId;
  const passwordToken=req.body.passwordToken;
  let resetUser;

  User.findOne({resetToken:passwordToken,resetTokenExpiration:{$gt: Date.now()},_id:userId})
  .then(user=>{
    resetUser=user;
    return bcrypt.hash(newPassword,12)
  }).then(hashedPassword=>{
    resetUser.password=hashedPassword;
    resetUser.resetToken=undefined;
    resetUser.resetTokenExpiration=undefined;
    return  resetUser.save()
}).then(result=>{
  res.redirect('/login')
}).catch(err=>{
  const error=new Error(err)
  error.httpStatusCode=500;
  next(error);
})
   
}