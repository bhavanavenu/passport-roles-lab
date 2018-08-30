const express = require('express');
const router = express.Router();
const User = require('../models/User');
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn;
const checkAdmin = checkRoles('Boss');



/* GET home page */
router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/employees', ensureLoggedIn('/auth/login'), (req, res, next) => {
  User.find().then(employees => {
    if (req.user.role === "Boss") {
      res.render('employees', { employees: employees, isBoss: true });
    } else {
      employees = employees.map( employee => {
        return employee._id.toString() === req.user._id.toString()
        ? { employee, isOwner: true }
        : { employee, isOwner: false }
      });
      res.render('employees', { employees } )
    }
  });
});

router.get('/private', ensureLoggedIn('/auth/login'), checkRoles('BOSS'), (req, res) => {
  res.render('private', {user: req.user});
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

module.exports = router;