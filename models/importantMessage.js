const mongoose = require('mongoose')

//Schemat wiadomości
const importantMessageschema = mongoose.Schema({
    author: { type: String },
    message: [{
        body: {type: String, min: 1, max: 200},
        createdAt: { type: Date }
    }]
})

module.exports = mongoose.model('importantMessages', importantMessageschema)