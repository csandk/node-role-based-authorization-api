const config = require('config.json');
const jwt = require('jsonwebtoken');
const Role = require('_helpers/role');

// users hardcoded for simplicity, store in a db for production applications
const users = [
    { id: 1, username: 'admin', password: 'admin', firstName: 'Admin', lastName: 'User', role: Role.Admin },
    { id: 2, username: 'user', password: 'user', firstName: 'ViewOnly', lastName: 'User', role: Role.User },
    { id: 3, username: 'editor', password: 'editor', firstName: 'Normal', lastName: 'User', role: Role.Editor }
];

var loggedInUserToken = null;
var editUserTimeout = null;
const timeoutInMinutes = 2;

module.exports = {
    authenticate,
    reauthenticate,
    getAll,
    getById,
    logout
};

async function authenticate({ username, password }) {
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        if (user.username == "editor" && loggedInUserToken) {
            console.log("editor logged in");
            return "editorBlocked";
        }
        const token = jwt.sign({ sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + (60 * timeoutInMinutes) }, config.secret);
        const { password, ...userWithoutPassword } = user;
        if (user.username == "editor") {
            loggedInUserToken = token;
            editUserTimeout = setTimeout(resetToken, timeoutInMinutes * 60000)
        }        
        return {
            ...userWithoutPassword,
            timeoutInMinutes,
            token
        };
    }
}

async function reauthenticate(oldUser) {
    const user = users.find(u => u.username === oldUser.username);
    
    if (user ) {
        try {
            jwt.verify(oldUser.token, config.secret)
        } catch (error) {
            logIt(error)
        }        
        const token = jwt.sign({ sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + (60 * timeoutInMinutes) }, config.secret);
        const { password, ...userWithoutPassword } = user;
        if (user.username == "editor" && loggedInUserToken) {
            clearTimeout(editUserTimeout);
            loggedInUserToken = token;
            editUserTimeout = setTimeout(resetToken, timeoutInMinutes * 60000)
        }                
        return {
            ...userWithoutPassword,
            timeoutInMinutes,
            token
        };
    }
}

async function logout(oldUser) {
    const user = users.find(u => u.username === oldUser.username);
    
    if (user) {
        logIt("foundUserToLogout");
        try {
            jwt.verify(oldUser.token, config.secret)
            logIt("verified")
        } catch (error) {
            logIt(error)
        }        
        if (user.username == "editor" && loggedInUserToken) {
            clearTimeout(editUserTimeout);
            loggedInUserToken = null;
        }                
        return true;
    }
    return false;
}

function logIt(word) {
    console.log(word);
}

function resetToken() {
    loggedInUserToken = null;
    console.log("reset Token")
}

async function getAll() {
    return users.map(u => {
        const { password, ...userWithoutPassword } = u;
        return userWithoutPassword;
    });
}

async function getById(id) {
    const user = users.find(u => u.id === parseInt(id));
    if (!user) return;
    const { password, ...userWithoutPassword } = user;
    return userWithoutPassword;
}