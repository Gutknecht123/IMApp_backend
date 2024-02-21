const mongoose = require('mongoose')

//Schemat wiadomości
const MessageSchema = mongoose.Schema({
    host: {type: String},
    username: {type: String},
    roomID: { type: String, unique: true },
    messages: [{
        body: {type: String, min: 1, max: 200},
        sender: {type: String},
        createdAt: { type: Date, default: Date.now },
        filePath: { type: String },
        fileName: { type: String }
    }],
    lastMessage: { type: Date, default: Date.now }
})

module.exports = mongoose.model('messages', MessageSchema)