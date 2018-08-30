const express = require('express');
const passport = require('passport');
const authRoutes = express.Router();
const User = require('../models/User');
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;
const checkAdmin = checkRoles('Boss');
// Bcrypt to encrypt passwords
const bcrypt = require('bcrypt');
const bcryptSalt = 10;

authRoutes.get('/login', (req, res, next) => {
  res.render('auth/login', { message: req.flash('error') });
});

authRoutes.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/auth/login',
    failureFlash: true,
    passReqToCallback: true
  })
);

authRoutes.get('/signup', ensureLoggedIn('/auth/login'), checkAdmin, (req, res, next) => {
  res.render('auth/signup');
});

authRoutes.post('/signup', ensureLoggedIn('/auth/login'), checkAdmin, (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const rol = req.body.role;
  if (username === '' || password === '') {
    res.render('auth/signup', { message: 'Indicate username and password' });
    return;
  }

  User.findOne({ username }, 'username', (err, user) => {
    if (user !== null) {
      res.render('auth/signup', { message: 'The username already exists' });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    const newUser = new User({
      username,
      password: hashPass
    });

    newUser.save(err => {
      if (err) {
        res.render('auth/signup', { message: 'Something went wrong' });
      } else {
        res.redirect('/');
      }
    });
  });
});

authRoutes.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

authRoutes.post('/:id/delete', (req, res, next) => {
  User.findByIdAndRemove(req.params.id).then(x => {
    res.redirect('back');
  });
});

authRoutes.get('/:id/edit', (req, res, next) => {
  User.findById(req.params.id).then(userFromDb => {
    res.render('edit-employee', userFromDb);
  });
});

authRoutes.post('/:id/edit', (req, res, next) => {
  console.log("hello")
  const userID = req.params.id;
  const { username, role } = req.body;
  User.update({ _id: userID }, { $set: { username, role } }, { new: true })
    .then(user => {
      res.redirect('/employees');
    })
    .catch(error => {
      console.log(error);
    });
});

authRoutes.get('/:id', (req, res, next) => {
  User.findById(req.params.id).then(userFromDb => {
    res.render('show', userFromDb);
  });
});

function checkRoles(role) {
  return function(req, res, next) {
    if (req.isAuthenticated() && req.user.role === role) {
      return next();
    } else {
      res.redirect('/login');
    }
  };
}

module.exports = authRoutes;