const express = require('express');
const router = express.Router()
const bcrypt = require('bcryptjs');
const passport = require('passport');

// User Model
const User = require('../models/User');

router.get('/login', (req, res) => {
    res.render('login')
});

router.get('/register', (req, res) => {
    res.render('register')
});

router.post('/register', (req, res) => {
    const {name, email, password, password2} = req.body

    const errors = []

    // Check for all required field
    if(!name || !email || !password || !password2) {
        errors.push({message: 'All fields are required'})
    }

    // Check for length of password
    if(password.length < 4) {
        errors.push({message: 'Password must be atleast 4 characters'})
    }

    // Check for password match
    if(password !== password2) {
        errors.push({message: 'Password do not match'})
    }

    if(errors.length > 0) {
        res.render('register', {errors, name, email, password, password2});
    } else {
        User.findOne({email: email})
        .then(user => {
            if(user) {
                errors.push({message: 'Email already exists'})
                res.render('register', {errors, name, email, password, password2});   
            } else {
                const newUser = new User({
                    name,
                    email,
                    password
                });
                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err;

                        newUser.password = hash

                        newUser.save()
                            .then(() => {
                                req.flash('success_msg', 'Your registration was successful')
                                res.redirect('/users/login')
                            })
                            .catch(err => console.log(err))
                    })
                })
            }
        })
    }
});

router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

router.get('/logout', (req, res) => {
    req.logOut();
    req.flash('success_msg', 'Logged out successfully');
    res.redirect('/users/login')
});
module.exports = router;