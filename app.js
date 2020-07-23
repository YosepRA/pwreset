var express = require('express');
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const async = require('async');
const crypto = require('crypto');
const flash = require('express-flash');

var app = express();

// User schema.
let userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});
// User middleware on save, hash the plain password before saving to DB.
userSchema.pre('save', function (next) {
  let user = this;
  const SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, (err, salt) => {
    // Providing "next" function an argument at its first position will represent an error.
    // This is a convenience pattern for middlewares that the "next" function will be given "err" as its ~
    // ~ first argument and followed by the real value for the next function to use.
    // Take a note that "next" function DOES NOT break the execution context, therefore if you need to ~
    // ~ break it, then use early returns or other execution breaking keywords.
    if (err) return next(err);

    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) return next(err);

      user.password = hash;
      next();
    });
  });
});
// User instance method. Every instance of User will have this method.
// Comparing between plain password given by user's form with the hashed password of the claimed user.
userSchema.methods.comparePassword = function (candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

let User = mongoose.model('User', userSchema);

// Passport setup.
// Strategy. It will check user's identity and pass information to the next function accordingly.
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username }, (err, user) => {
      if (err) return done(err);

      if (!user) return done(null, false, { message: 'Incorrect username' });

      user.comparePassword(password, (err, isMatch) => {
        if (isMatch) return done(null, user);
        else return done(null, false, { message: 'Incorrect password' });
      });
    });
  })
);
// serializeUser. This will serialize the user object to "req.session.passport.user = { /* serialized user ID */ }".
// What's contained in the passport session will be used as future reference if another request comes.
passport.serializeUser((user, done) => {
  done(null, user.id);
});
// deserializeUser. This will add completed user object to "req.user" so that it will available for each requests.
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

// DB setup.
mongoose.connect('mongodb://localhost:27017/pwreset', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Database connection error: '));
db.on('open', () => console.log('Successfully connected to the Database...'));

// Middleware
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: 'This is a secret',
    saveUninitialized: false,
    resave: false,
  })
);
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

// ROUTES
// Home.
app.get('/', (req, res) => {
  // Passing "user" to template will signify whether there is a signed in user or not.
  res.render('index', { title: 'Express', user: req.user });
});

// Login form.
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', user: req.user });
});

// Login.
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect('/login');
    req.login(user, err => {
      if (err) next(err);
      res.redirect('/');
    });
  })(req, res, next);
});

// Signup form.
app.get('/signup', (req, res) => {
  res.render('signup', { title: 'Signup', user: req.user });
});

// Signup.
app.post('/signup', (req, res) => {
  let { username, email, password } = req.body;

  let newUser = new User({ username, email, password });

  newUser.save(err => {
    if (err) {
      console.log(err);
    } else {
      req.login(newUser, err => {
        if (err) console.log(err);
        res.redirect('/');
      });
    }
  });
});

// Logout.
app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

// Forgot password.
app.get('/forgot', (req, res) => {
  res.render('forgot', { user: req.user });
});

app.post('/forgot', (req, res, next) => {
  async.waterfall(
    [
      function (done) {
        crypto.randomBytes(20, (err, buf) => {
          let token = buf.toString('hex');
          done(err, token);
        });
      },
      function (token, done) {
        User.findOne({ email: req.body.email }, (err, user) => {
          if (!user) {
            req.flash('error', 'No account with that email address exist.');
            return res.redirect('/');
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000;

          user.save(err => {
            done(err, token, user);
          });
        });
      },
      function (token, user, done) {
        const transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          auth: {
            user: 'flavio16@ethereal.email',
            pass: 'vCttTme1rHqEerENm3',
          },
        });

        let mailOptions = {
          to: user.email,
          from: 'passwordreset@demo.com',
          subject: 'Node.js Password Reset',
          text:
            'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' +
            req.headers.host +
            '/reset/' +
            token +
            '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n',
        };

        transporter.sendMail(mailOptions, err => {
          req.flash(
            'info',
            'An e-mail has been sent to ' +
              user.email +
              ' with further instruction.'
          );
          done(err, 'done');
        });
      },
    ],
    err => {
      if (err) return next(err);
      res.redirect('/forgot');
    }
  );
});

app.get('/reset/:token', (req, res) => {
  User.findOne(
    {
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    },
    (err, user) => {
      if (!user) {
        req.flash('error', 'Password reset token is invalid or has expired.');
        return res.redirect('/forgot');
      }
      res.render('reset', { user: req.user });
    }
  );
});

app.post('/reset/:token', (req, res) => {
  async.waterfall(
    [
      function (done) {
        User.findOne(
          {
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
          },
          (err, user) => {
            if (!user) {
              req.flash(
                'error',
                'Password reset token is invalid or has expired.'
              );
              return res.redirect('/forgot');
            }

            user.password = req.body.password;
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            user.save(err => {
              req.login(user, err => {
                done(err, user);
              });
            });
          }
        );
      },
      function (user, done) {
        const transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          auth: {
            user: 'flavio16@ethereal.email',
            pass: 'vCttTme1rHqEerENm3',
          },
        });

        let mailOptions = {
          to: user.email,
          from: 'passwordreset@demo.com',
          subject: 'Your password has been changed',
          text: `Hello
          
          This is a confirmation that the password for your account ${user.email} has been changed.`,
        };

        transporter.sendMail(mailOptions, err => {
          req.flash('success', 'Success! Your password has been changed.');
          done(err, 'done');
        });
      },
    ],
    err => res.redirect('/')
  );
});

app.listen(app.get('port'), function () {
  console.log('Express server listening on port ' + app.get('port'));
});
