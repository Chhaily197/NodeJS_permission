const express = require('express');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true}));
app.use(cookieParser());

const secretKey = crypto.randomBytes(64).toString('hex');

//import user filePath, Because I'm not use database
const userData = require('./users.json');

app.use(express.static(path.join(__dirname, 'public')));

app.get('/login', (req, res) => {
    try{
        res.sendFile(path.join(__dirname, '/public/login.html'));
    }catch(err){
        console.error('Error serving login.html');
        res.status(500).send('Internal server Error');
    }
})

app.post('/login', (req, res)  => {
    const { username, password } = req.body;

            const user = userData.users.find(
                (u) => u.username === username && u.password === password
            );

        if(user){
            //Assuming the use of JWT for token generation
            const token = jwt.sign({ username: user.username, role: user.role}, secretKey, { expiresIn: '1h'});

            res.cookie('token', token, { maxAge: 900000, httpOnly: true});

            if(user.role === 'admin'){
                res.redirect(`/dashboard?username=${username}`);
            }else{
                res.redirect(`/home?username=${username}`);
            }
            // res.json({ msg: 'Login successful'});
        }else{
            res.status(401).send('Invalid username or password');
            res.redirect('/login');
        }
});

app.get('/home', (req, res) => {
    if(req.cookies.token){
        const token = req.cookies.token;

        jwt.verify(token, secretKey, (err, decoded) => {
            if(err){
                res.redirect('/login');
            }else{
                const user = userData.users.find((u) => u.username === decoded.username);
                if(user && user.role === 'user'){
                res.sendFile(path.join(__dirname, '/public/home.html'));
                }else{
                    res.redirect('/login');
                }
            }
        })
    }else{
        res.redirect('/login');
    }
});

app.get('/dashboard', (req, res) => {
    if(req.cookies.token){
        const token = req.cookies.token; // Get the token from the cookie

        jwt.verify(token, secretKey, (err, decoded) => {
            if(err){
                res.redirect('/login');
            }else{
                const user = userData.users.find((u) => u.username === decoded.username);

                if(user && user.role === 'admin'){
                    res.sendFile(path.join(__dirname, '/public/dashboard.html'));
                }else{
                    res.redirect('/login');
                }
            }
        })
    }else{
        res.redirect('/login');
    }
})

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login')
});

function requiredLogin(req, res, next) {
    if(req.cookies.loggedIn ===  true){
        next();
    }else{
        res.status(401).send('Unauthorized');
    }
}

//Example protected route
app.get('/protected',requiredLogin, (req, res) => {
    if(req.cookies.token){
        res.json({ msg: "Access granted to protected route"});
    }
})

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
})