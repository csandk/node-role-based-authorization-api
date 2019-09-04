const express = require('express');
const router = express.Router();
const userService = require('./user.service');
const authorize = require('_helpers/authorize')
const Role = require('_helpers/role');

// routes
router.post('/authenticate', authenticate);     // public route
router.post('/reauthenticate', reauthenticate);     // public route
router.get('/', authorize(Role.Admin), getAll); // admin only
router.get('/:id', authorize(), getById);       // all authenticated users
router.post('/logout', logout);       // all authenticated users
module.exports = router;

function authenticate(req, res, next) {
    console.log("login")
    userService.authenticate(req.body)
        .then(user => {
            if (user == "editorBlocked") {
                res.status(400).json({ message: 'User Editor is currently in use' })
            } else if (user) {
                res.json(user)
            } else {
                res.status(400).json({ message: 'Username or password is incorrect' })
            }
        }//user ? res.json(user) : res.status(400).json({ message: 'Username or password is incorrect' })
        )
        .catch(err => next(err));
}

function reauthenticate(req, res, next) {
    userService.reauthenticate(req.body)
        .then(user => {
            if(user) {
                res.json(user)
            } else {
                res.status(400).json({ message: 'User not found or invalid token' })
            }
        })
        .catch(err => next(err));
}

function logout(req, res, next) {
    console.log("logout")
    userService.logout(req.body)
        .then(result => {
            if(result) {
                res.json(result)
            }
        })
        .catch(err => next(err));
}

function getAll(req, res, next) {
    userService.getAll()
        .then(users => res.json(users))
        .catch(err => next(err));
}

function getById(req, res, next) {
    const currentUser = req.user;
    const id = parseInt(req.params.id);

    // only allow admins to access other user records
    if (id !== currentUser.sub && currentUser.role !== Role.Admin) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    userService.getById(req.params.id)
        .then(user => user ? res.json(user) : res.sendStatus(404))
        .catch(err => next(err));
}