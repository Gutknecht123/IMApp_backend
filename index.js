//init
const bodyParser = require('body-parser')
const express = require('express')
const mongoose = require('mongoose')
const User = require('./models/user')
const Message = require('./models/message')
const importantMessage = require('./models/importantMessage')
require('dotenv').config()
const app = express()
const cors = require('cors')
const http = require('http').createServer(app)
const fs = require('fs')
const jwt = require('jsonwebtoken')
var crypto = require('crypto')
const io = require('socket.io')(http)
var nodemailer = require('nodemailer')
const multer  = require('multer');


const transporter = nodemailer.createTransport({
    service: 'gmail',
    port: 465,
    host: "smtp.gmail.com",
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASS
    },
    secure: true
})

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/')
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname)
    }
})

const upload = multer({ storage: storage })

var MONGODB_URI = process.env.MONGO_URI

mongoose.connect(MONGODB_URI)
mongoose.connection.on('connected', ()=>{
    console.log("Connected")
})

//Middleware
var jsonParser = bodyParser.json()
var urlencodedParser = bodyParser.urlencoded({ extended: false })
app.use(cors({
    origin: '*'
}))

function authenticateToken(req,res,next){

    try{
        const authHeader = req.headers['authorization']
        const token = authHeader && authHeader.split(' ')[1]

        if(token == null) return res.sendStatus(401)

        jwt.verify(token, process.env.TOKEN_SECRET, (err, user)=>{
            
            if(err) return res.sendStatus(403)

            req.user = user

            next()
        })
    }catch(err){
        console.log(err)
    }
}

//API

function generateAccessToken(name, password){
    //Zwracamy json web token
    return jwt.sign(name, process.env.TOKEN_SECRET, { expiresIn: '20000s' })
}

function validatePassword(password, userHash, userSalt){
    var hash = crypto.pbkdf2Sync(password, userSalt, 1000, 64, 'sha512').toString('hex')
    return userHash === hash
}

app.get('/', async(req, res) => {
    res.send({status: 'OK'})
})

app.post('/api/fileUpload', upload.single('file'), (req, res) => {
    console.log('plik')
    if(!req.file){
        return res.status(400).json({ error: 'Brak pliku' })
    }

    return res.status(200).json({ message: 'Plik przeslany' })
})

app.get('/api/messages', async(req, res) => {

    try{
        const chat = await Message.find({ username: req.query.username })
        let count = req.query.count
        //console.log(chat[0].messages)

        const mess = chat[0].messages

        let tab = []
        console.log(count)
        if(mess.length > 0){
            if(parseInt(count) > mess.length){
                count = mess.length
            }
            for(var i=0; i < count; i++){
                tab.unshift(mess[(mess.length - 1) - i])
            }
        }

        console.log(tab)
 
        res.json(tab)

    }catch(err){
        return res.status(400)
    }
})

app.get('/api/officemessages', async(req, res) => {

    try{
        const projection = { name: 1, email: 1, role: 1, surname: 1, username: 1, _id: 0 }
        const users = await User.find({}, 'name surname email role username roomID')
        //let count = req.query.count
        //console.log(chat[0].messages)
        console.log("To users")
        console.log(users)

        res.json(users)

    }catch(err){
        return res.status(400)
    }
})

app.get('/api/importantmessages', async(req, res) => {
    try{

        const im = await importantMessage.find({})
        res.json(im)

    }catch(err){
        return res.status(400)
    }

})

app.get('/api/download/:fileName', async(req, res) => {
    try{
        
        path = require('path')
        const data = req.params.fileName
        res.sendFile(path.join(__dirname, './uploads/' +data))

    }catch(err){
        return res.status(400)
    }
})

//Logowanie użytkownika i przypisanie json web token
app.post('/api/userLogin', jsonParser, async (req, res)=>{

    try{
        //Szukamy użytwkonika w bazie
        const user = await User.find({ email: req.body.email })
        if(user.length == 0){
            return res.status(400).send({ 
                message : "Nie znaleziono użytkownika"
            })
        }else{
            //Sprawdzamy czy dane się zgadzają
            if(validatePassword(req.body.password, user[0].hash, user[0].salt)){
                const token = generateAccessToken( { name: req.body.email, password: req.body.password} )

                const data = {
                    data: {
                        jwt: token,
                        username: user[0].username,
                        name: user[0].name,
                        surname: user[0].surname,
                        role: user[0].role,
                        email: user[0].email,
                        roomID: user[0].roomID
                    }
                }

                res.json(data)
            }else{
                return res.status(400).send({ 
                    message : "Błędne hasło"
                })
            }
        }

    }catch(err){
        console.log(err)
        return res.status(400).send({ 
            message: "Błąd podczas logowania"
        })
    }
})

app.post('/api/userRegister', jsonParser, async (req, res, next) => {

    try{
        let newUser = new User()
        let newMessage = new Message()
        var salt, hash

        //Haszujemy hasło użytkownika
        //newUser.setPassword(req.body.password)

         //Tworzymy unikalny salt dla użytkownika
        salt = crypto.randomBytes(16).toString('hex')

        //Haszowanie hasła i salt użytkownika w 1000 iteracji
        hash = crypto.pbkdf2Sync(req.body.password, salt, 1000, 64, 'sha512').toString('hex')

        let rand = Math.floor(Math.random() * 100000) + 1

        let room = "room_"+rand.toString()

        const temp = await User.find({roomID: room})

        console.log(temp)

        if(temp != ''){
            do{

                rand = Math.floor(Math.random() * 100000) + 1
                room = "room_"+rand.toString()

            }while(temp[0].roomID == room)
        }

        //Przypisanie danych do obiektu newUser
        newUser.name = req.body.name
        newUser.email = req.body.email
        newUser.role = req.body.role
        newUser.surname = req.body.surname
        newUser.username = req.body.username
        newUser.roomID = room
        newUser.salt = salt
        newUser.hash = hash
        newMessage.host = "biuro"
        newMessage.username = req.body.username
        newMessage.roomID = room
        newMessage.messages = [
            {
                body: "To początek twoich wiadomości z naszym biurem",
                sender: "biuro",
                createdAt: ""
            }
        ]
        //Zapisujemy użytkownika do bazy
        await newUser.save()
        await newMessage.save()

        const mailData = {
            from: "imappnotifier@gmail.com",
            to: req.body.email,
            subject: "Twoje konto zostało założone!",
            text: `Zostałeś dodany do korzystania z aplikacji Hillconnect Hub! Oto twoje dane logowania. Login: ${req.body.username} Hasło: ${req.body.password}`,
            html: `<b>Zostałeś dodany do korzystania z aplikacji Hillconnect Hub!</b><br>Oto twoje dane logowania.<br>Login: ${req.body.username} <br> Hasło: ${req.body.password}</br>`
        }

        transporter.sendMail(mailData, (err, info)=>{
            if(err){
                return console.log(err)
            }
        })

        return res.status(201).send({ 
            message: "Pomyślnie dodano użytkownika"
        })
    }catch (err){
        console.log(err)
        return res.status(400).send({ 
            message: "Nie udało się dodać użytkownika"
        })
    }
})

app.get('/api/test', (req, res)=>{
    res.send({status: 'OK'})
})

//Socket
io.use((socket, next) => {
    const sessionID = socket.handshake.auth.sessionID;
    if (sessionID) {
      // find existing session
      const session = sessionStore.findSession(sessionID);
      if (session) {
        socket.sessionID = sessionID;
        socket.userID = session.userID;
        socket.username = session.username;
        return next();
      }
    }
    const username = "test";
    if (!username) {
      return next(new Error("invalid username"));
    }
    // create new session
    socket.sessionID = 5
    socket.userID = 123
    socket.username = username;
    next();
  });

io.on('connection', (socket) => {
    console.log(socket.id)
    socket.emit("session", {
        sessionID: socket.sessionID,
        userID: socket.userID,
    });

    socket.on('private_message', async(data)=>{
        console.log(data.file)
        let filePath = null
        let url = null
        let fileName = null
        if(data.file != null){

            const formData = data.file
            fileName = formData
     
            filePath = __dirname + '/uploads/' + fileName
            url = 'uploads/' + fileName
        
            console.log(fileName)
       

        }

        await Message.updateOne(
            { username: data.username },
            {
                $set:{
                    username: data.username
                },
                $push:{
                    messages: {
                        body: data.message,
                        sender: data.sender,
                        createdAt: "",
                        filePath: url,
                        fileName: fileName
                    }
                }
            },
            {upsert: true}
        )
        //const chat = await Message.find({ username: data.username })
        socket.to(data.room).emit("private_message", data)
    })

    socket.on('file_upload', async(data)=>{
        const filePath = __dirname + '/uploads/' + data.filename
        fs.writeFile(filePath, data.filedata, 'base64', (err)=>{
            if (err) throw err;
            console.log('Zapisano')

            //
            //socket.to(data.room).emit("private_message", data)
        })
    })

    socket.on('important_message', async(data)=>{

        let newIM = new importantMessage()

        newIM.author = data.author
        newIM.message = [{
            body: data.body,
            createdAt: ""
        }]

        await newIM.save()

        io.emit("new_important_message", data)
        console.log("done")
    })

    socket.on("join_room", (data)=>{
        socket.join(data)
        console.log("user joined "+ data)
    })
    socket.on('leaveRoom', (roomName) => {
        console.log(`User left room: ${roomName}`)
        socket.leave(roomName)
    })

})

const hostname = "192.168.100.2"
const PORT = process.env.PORT || 3000
http.listen(PORT, ()=>{
    console.log(`App running on port ${ PORT }`)
})