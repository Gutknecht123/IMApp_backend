const mongoose = require('mongoose')

//Schemat użytkowników
const UserSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    surname: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    role: {
        type: String,
        required: true 
    },
    email: {
        type: String,
        required: true
    },
    roomID: {
        type: String,
        required: true
    },
    hash: String,
    salt: String
})

module.exports = mongoose.model('users', UserSchema)