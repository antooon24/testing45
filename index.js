import express from 'express';
import { Issuer, TokenSet, custom, generators } from 'openid-client';
import cookieParser from 'cookie-parser';
import admin from 'firebase-admin';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

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

const robloxClientId = process.env.ROBLOX_CLIENT_ID;
const robloxClientSecret = process.env.ROBLOX_CLIENT_SECRET;
const discordClientId = process.env.DISCORD_CLIENT_ID;
const discordClientSecret = process.env.DISCORD_CLIENT_SECRET;

const robloxRedirectUri = `https://testing45.onrender.com/oauth/roblox-callback`;
const discordRedirectUri = `https://testing45.onrender.com/oauth/discord-callback`;

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
        // Roblox Issuer and Client
        const robloxIssuer = await Issuer.discover('https://apis.roblox.com/oauth/.well-known/openid-configuration');
        const robloxClient = new robloxIssuer.Client({
            client_id: robloxClientId,
            client_secret: robloxClientSecret,
            redirect_uris: [robloxRedirectUri],
            response_types: ['code'],
            scope: 'openid profile',
        });

        robloxClient[custom.clock_tolerance] = 180;

        // Discord Issuer and Client
        const discordIssuer = await Issuer.discover('https://discord.com/.well-known/openid-configuration');
        const discordClient = new discordIssuer.Client({
            client_id: discordClientId,
            client_secret: discordClientSecret,
            redirect_uris: [discordRedirectUri],
            response_types: ['code'],
            scope: 'identify openid',
        });

        discordClient[custom.clock_tolerance] = 180;

        async function checkLoggedIn(req, res, next) {
            if (req.signedCookies.robloxTokenSet && req.signedCookies.discordTokenSet) {
                let robloxTokenSet = new TokenSet(req.signedCookies.robloxTokenSet);
                let discordTokenSet = new TokenSet(req.signedCookies.discordTokenSet);

                if (robloxTokenSet.expired()) {
                    robloxTokenSet = await robloxClient.refresh(robloxTokenSet.refresh_token);
                    res.cookie('robloxTokenSet', robloxTokenSet, secureCookieConfig);
                }

                if (discordTokenSet.expired()) {
                    discordTokenSet = await discordClient.refresh(discordTokenSet.refresh_token);
                    res.cookie('discordTokenSet', discordTokenSet, secureCookieConfig);
                }

                req.robloxTokenSet = robloxTokenSet;
                req.discordTokenSet = discordTokenSet;
                next();
            } else {
                res.redirect('/login');
            }
        }

        app.get('/', checkLoggedIn, (req, res) => {
            res.redirect('/home');
        });

        app.get('/login', (req, res) => {
            res.redirect('/login/roblox');
        });

        app.get('/login/roblox', (req, res) => {
            const state = generators.state();
            const nonce = generators.nonce();
            res.cookie('state', state, secureCookieConfig)
               .cookie('nonce', nonce, secureCookieConfig)
               .redirect(robloxClient.authorizationUrl({
                   scope: robloxClient.scope,
                   state,
                   nonce,
               }));
        });

        app.get('/oauth/roblox-callback', async (req, res) => {
            const params = robloxClient.callbackParams(req);
            const state = req.signedCookies.state;
            const nonce = req.signedCookies.nonce;

            if (!state || !nonce) {
                console.error('State or nonce missing in cookies');
                return res.status(400).send('State or nonce missing in cookies');
            }

            try {
                const robloxTokenSet = await robloxClient.callback(robloxRedirectUri, params, { state, nonce });
                res.cookie('robloxTokenSet', robloxTokenSet, secureCookieConfig)
                   .clearCookie('state')
                   .clearCookie('nonce')
                   .redirect('/login/discord');

                const userClaims = robloxTokenSet.claims();
                console.log('Roblox User Claims:', userClaims);

                const userData = {
                    name: userClaims.name,
                    nickname: userClaims.preferred_username,
                    profile: userClaims.profile,
                    picture: userClaims.picture || null, // Handle missing picture
                };

                await db.ref(`users/${userClaims.sub}`).set(userData);

            } catch (error) {
                console.error('Error handling Roblox OAuth callback:', error);
                res.status(500).send('Error handling Roblox OAuth callback');
            }
        });

        app.get('/login/discord', (req, res) => {
            const state = generators.state();
            res.cookie('state', state, secureCookieConfig)
               .redirect(discordClient.authorizationUrl({
                   scope: discordClient.scope,
                   state,
                   redirect_uri: discordRedirectUri,
               }));
        });

        app.get('/oauth/discord-callback', async (req, res) => {
            const params = discordClient.callbackParams(req);
            const state = req.signedCookies.state;

            if (!state) {
                console.error('State missing in cookies');
                return res.status(400).send('State missing in cookies');
            }

            try {
                const discordTokenSet = await discordClient.callback(discordRedirectUri, params, { state });
                res.cookie('discordTokenSet', discordTokenSet, secureCookieConfig)
                   .clearCookie('state')
                   .redirect('/home');

                const userClaims = discordTokenSet.claims();
                console.log('Discord User Claims:', userClaims);

                // Link Roblox and Discord IDs in Firebase
                const robloxId = req.robloxTokenSet ? req.robloxTokenSet.claims().sub : null;
                const discordId = userClaims.sub;

                if (robloxId) {
                    await db.ref(`users/${robloxId}`).update({ discordId });
                }

                await db.ref(`users/${discordId}`).update({ robloxId });

            } catch (error) {
                console.error('Error handling Discord OAuth callback:', error);
                res.status(500).send('Error handling Discord OAuth callback');
            }
        });

        app.get('/home', checkLoggedIn, (req, res) => {
            const robloxUserData = req.robloxTokenSet ? req.robloxTokenSet.claims() : {};
            const discordUserData = req.discordTokenSet ? req.discordTokenSet.claims() : {};
            res.send(`Roblox User: ${robloxUserData.name}, Discord User: ${discordUserData.username}`);
        });

        app.listen(port, () => {
            console.log(`Server is running on http://localhost:${port}`);
        });
    } catch (error) {
        console.error('Error in main execution:', error);
        process.exit(1);
    }
}

main();
