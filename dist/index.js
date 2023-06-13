"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const session = require('express-session');
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use((req, res, next) => {
    // Set the allowed origin(s)
    res.setHeader('Access-Control-Allow-Origin', process.env.CLIENT_URL + `${req.baseUrl}`);
    // Allow the credentials to be sent
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    // Set the allowed methods
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    // Set the allowed headers
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});
app.use(session({
    secret: '23432eedsfdsf',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
    },
}));
app.use((0, cookie_parser_1.default)());
app.use((0, cors_1.default)({
    origin: process.env.CLIENT_URL,
}));
passport.use(new GoogleStrategy({
    clientID: "213951758323-hqk1f68rdgq1nkmsjro1bdg5to6pjgou.apps.googleusercontent.com",
    clientSecret: "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",
    callbackURL: 'https://ai-interview-project-api.vercel.app/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
    // This callback function is called after successful authentication
    // You can perform any necessary user data handling here
    // For example, create a new user in your database or retrieve an existing user
    // Then call the done() function to proceed with the authentication process
    done(null, profile);
}));
app.use(passport.initialize());
app.use(passport.session());
app.get('/', (req, res) => {
    res.send('Hello Deploy Succesfull');
});
passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((user, done) => {
    // Find the user by ID in your database or data source
    done(null, user);
});
// Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', "email"] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login/failed',
    successRedirect: process.env.CLIENT_URL + '/interview'
}));
const VerifyRefreshToken = (req, res, next) => {
    const cookies = req.cookies;
    if (!cookies?.jwt)
        return res.json({ err: 'No Cookie Found' });
    jsonwebtoken_1.default.verify(cookies.jwt, process.env.REFRESH_TOKEN_SECRET, (err, decode) => {
        if (err)
            return res.status(401).json({ err });
        const { fullname, password, email } = decode;
        if (!fullname || !password || !email)
            return res.status(401).json({ err: 'missing some payload' });
        req.body = { fullname, password, email };
    });
    next();
};
const verifyGoogleAuth = (req, res, next) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) {
        return next();
    }
    else {
        jsonwebtoken_1.default.verify(cookies.jwt, process.env.REFRESH_TOKEN_SECRET, (err, decode) => {
            if (err) {
                return res.status(401).json({ err });
            }
            else {
                return res.status(200).json({
                    success: true,
                    user: decode,
                });
            }
        });
    }
};
app.get('/login/success', verifyGoogleAuth, (req, res) => {
    if (req.user) {
        const refreshToken = jsonwebtoken_1.default.sign(req.user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30s' });
        res.cookie('jwt', refreshToken, {
            httpOnly: true,
            maxAge: 1000 * 30,
            secure: process.env.NODE_ENV === 'production',
        });
        return res.status(200).json({
            success: true,
            user: req.user,
        });
    }
    else
        return res.status(401).send("Unauthorized");
});
app.get('/login/failed', (req, res) => {
    res.send('Login Failed');
});
app.post('/signup', (req, res) => {
    const f = req.body;
    if (!f.fullname || !f.password || !f.email)
        return res.status(400).json({ err: 'missing some payload' });
    const refreshToken = jsonwebtoken_1.default.sign(f, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30d' });
    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 30,
        secure: true,
    });
    return res.send('Succesfull');
});
app.get('/token', VerifyRefreshToken, (req, res) => {
    const accessToken = jsonwebtoken_1.default.sign(req.body, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
    res.json({ accessToken });
});
app.listen(5000, () => {
    console.log('listening at PORT 3000');
});
exports.default = app;
