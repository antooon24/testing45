import express from 'express';
import { Issuer, TokenSet, custom, generators } from 'openid-client';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import axios from 'axios';
import admin from 'firebase-admin';
import { Buffer } from 'buffer';

// Load environment variables from .env file
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Decode Base64-encoded Firebase service account key
const base64ServiceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
const serviceAccountKey = JSON.parse(Buffer.from(base64ServiceAccountKey, 'base64').toString('utf-8'));

// Initialize Firebase Admin SDK
admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey),
    databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.database();
const app = express();
const port = process.env.PORT || 3000;

const clientId = process.env.DISCORD_CLIENT_ID;
const clientSecret = process.env.DISCORD_CLIENT_SECRET;
const redirectUri = `https://testing45.onrender.com/oauth/discord-callback/`;
const cookieSecret = process.env.COOKIE_SECRET || 'random_secret_string';
const secureCookieConfig = {
    secure: process.env.NODE_ENV === 'production', // Set to true in production with HTTPS
    httpOnly: true,
    signed: true,
};

app.use(cookieParser(cookieSecret));
app.use(express.urlencoded({ extended: true }));

async function main() {
    try {
        const discordIssuer = await Issuer.discover('https://discord.com/.well-known/openid-configuration');
        const discordClient = new discordIssuer.Client({
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uris: [redirectUri],
            response_types: ['code'],
            scope: 'identify openid',
        });

        discordClient[custom.clock_tolerance] = 180;

        async function checkLoggedIn(req, res, next) {
            if (req.signedCookies.tokenSet) {
                let tokenSet;

                try {
                    tokenSet = req.signedCookies.tokenSet;
                    if (typeof tokenSet === 'string') {
                        tokenSet = JSON.parse(tokenSet);
                    }

                    if (typeof tokenSet !== 'object' || tokenSet === null) {
                        throw new Error('tokenSet is not a valid object');
                    }
                } catch (parseError) {
                    console.error('Error parsing tokenSet:', parseError);
                    return res.status(400).send('Invalid token data');
                }

                // Check token expiration and refresh if necessary
                if (new Date().getTime() / 1000 >= tokenSet.expires_at) {
                    try {
                        const refreshedTokenSet = await discordClient.refresh(tokenSet.refresh_token);
                        res.cookie('tokenSet', JSON.stringify(refreshedTokenSet), secureCookieConfig);
                        tokenSet = refreshedTokenSet;
                    } catch (refreshError) {
                        if (refreshError.error === 'invalid_grant') {
                            console.warn('Refresh token is invalid or expired. Prompting re-authentication.');
                            res.clearCookie('tokenSet');
                            res.clearCookie('state');
                            return res.redirect('/login');
                        } else {
                            console.error('Error refreshing token:', refreshError);
                            return res.status(500).send('Error refreshing token');
                        }
                    }
                }

                req.tokenSet = tokenSet;
                next();
            } else {
                res.redirect('/login');
            }
        }

        // Routes
        app.get('/', checkLoggedIn, (req, res) => {
            console.log('Token Set at /:', req.signedCookies.tokenSet);  // Debugging log
            res.redirect('/home');
        });

        app.get('/login', (req, res) => {
            const state = generators.state();
            res.cookie('state', state, secureCookieConfig)
                .redirect(discordClient.authorizationUrl({
                    scope: discordClient.scope,
                    state,
                    redirect_uri: redirectUri,
                }));
        });

        app.get('/oauth/discord-callback/', async (req, res) => {
            const params = discordClient.callbackParams(req);
            const state = req.signedCookies.state;

            if (!state) {
                console.error('State missing in cookies');
                return res.status(400).send('State missing in cookies');
            }

            try {
                const tokenSet = await discordClient.callback(redirectUri, params, { state });

                res.cookie('tokenSet', JSON.stringify(tokenSet), secureCookieConfig);
                res.redirect('/home');
            } catch (error) {
                console.error('Error during Discord OAuth callback:', error);
                res.status(500).send('Error during Discord OAuth callback');
            }
        });

        app.get('/home', checkLoggedIn, async (req, res) => {
            const tokenSet = req.tokenSet || {};
            const accessToken = tokenSet.access_token;

            try {
                const userInfoResponse = await axios.get('https://discord.com/api/users/@me', {
                    headers: {
                        Authorization: `Bearer ${accessToken}`
                    }
                });

                const userInfo = userInfoResponse.data;
                console.log('User Info:', userInfo);  // Debug log

                // Save user data to Firebase Realtime Database
                const ref = db.ref('users/' + userInfo.id);
                await ref.set(userInfo);

                res.send(`Welcome ${userInfo.username || 'Guest'}`);
            } catch (error) {
                console.error('Error fetching user info:', error);
        
