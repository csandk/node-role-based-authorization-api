const config = require('config.json');
const jwt = require('jsonwebtoken');
const Role = require('_helpers/role');

// users hardcoded for simplicity, store in a db for production applications
const users = [
    //{ id: 1, username: 'admin', password: 'admin', firstName: 'Admin', lastName: 'User', role: Role.Admin },
    { id: 2, username: 'user', password: 'user', firstName: 'ViewOnly', lastName: 'User', role: Role.User },
    { id: 3, username: 'editor', password: 'editor', firstName: 'Normal', lastName: 'User', role: Role.Editor },
    { id: 4, username: 'csandkuhler', password: 'csandkuhler', firstName: 'Christian', lastName: 'Sandkuehler', role: Role.Admin },
    { id: 5, username: 'acavlina', password: 'acavlina', firstName: 'Ante', lastName: 'Cavlina', role: Role.Editor },
    { id: 6, username: 'mneumann', password: 'mneumann', firstName: 'Marko', lastName: 'Neumann', role: Role.Editor },
    { id: 7, username: 'jschleef', password: 'jschleef', firstName: 'Juergen', lastName: 'Schleef', role: Role.Editor },
    { id: 8, username: 'bkoos', password: 'bkoos', firstName: 'Bjoern', lastName: 'Koos', role: Role.Editor },
    { id: 9, username: 'bott', password: 'bott', firstName: 'Bjoern', lastName: 'Ott', role: Role.Editor },
    { id: 10, username: 'riordache', password: 'riordache', firstName: 'Raluca', lastName: 'Iordache', role: Role.Editor },
    { id: 11, username: 'tbiel', password: 'tbiel', firstName: 'Thomas', lastName: 'Biel', role: Role.Editor },
    { id: 12, username: 'lfockele', password: 'lfockele', firstName: 'Lars', lastName: 'Fockele', role: Role.Editor }
];

var loggedInUserToken = null;
var editUserTimeout = null;
const timeoutInMinutes = 2;

//new vars
var userLockingEdit = null;
var editLockTimeout = null;
const editLockTimeoutInMinutes = 1;

module.exports = {
    authenticate,
    reauthenticate,
    getAll,
    getById,
    logout,
    lockEdit,
    freeEdit
};

async function authenticate({ username, password }) {
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        const token = jwt.sign({ sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + (60 * timeoutInMinutes) }, config.secret);
        const { password, ...userWithoutPassword } = user;     
        return {
            ...userWithoutPassword,
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
        }        
        const token = jwt.sign({ sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + (60 * timeoutInMinutes) }, config.secret);
        const { password, ...userWithoutPassword } = user;            
        return {
            ...userWithoutPassword,
            token
        };
    }
}

async function logout(oldUser) {
    const user = users.find(u => u.username === oldUser.username);
    
    if (user) {
        try {
            jwt.verify(oldUser.token, config.secret)
        } catch (error) {
        }        
        if (userLockingEdit && user.username == userLockingEdit.username) {
            clearTimeout(editLockTimeout);
            userLockingEdit = null;
        }                
        return true;
    }
    return false;
}

async function lockEdit(oldUser) {
    const user = users.find(u => u.username === oldUser.username);
    
    if (user && (user.role == Role.Editor || user.role == Role.Admin)) {
        try {
            jwt.verify(oldUser.token, config.secret)
        } catch (error) {
        }  
        if(userLockingEdit) {
            if(userLockingEdit.username == user.username) {
                clearTimeout(editLockTimeout);
                editLockTimeout = setTimeout(resetEdit, editLockTimeoutInMinutes * 60000);
                return true;
            }
            return userLockingEdit;            
        } else {
            const { password, ...userWithoutPassword } = user;
            userLockingEdit = userWithoutPassword;
            clearTimeout(editLockTimeout);
            editLockTimeout = setTimeout(resetEdit, editLockTimeoutInMinutes * 60000);
            return true;
        }
    }
    return false;
}

function resetEdit() {
    userLockingEdit = null;
    clearTimeout(editLockTimeout);
}

async function freeEdit(oldUser) {
    const user = users.find(u => u.username === oldUser.username);
    
    if (user && user.username == userLockingEdit.username) {
        try {
            jwt.verify(oldUser.token, config.secret)
        } catch (error) {
        }  
        resetEdit();
        return true;
    }
    return false;
}

function logIt(word) {
    console.log(word);
}

function resetToken() {
    loggedInUserToken = null;
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