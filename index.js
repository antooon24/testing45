import express from 'express';
import { Issuer, custom, generators } from 'openid-client';
import cookieParser from 'cookie-parser';
import admin from 'firebase-admin';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Firebase initialization
const serviceAccountJson = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(serviceAccountJson);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
});

const db = admin.database();
const app = express();
const port = process.env.PORT || 3000;

// Discord OAuth configuration
const clientId = process.env.DISCORD_CLIENT_ID;
const clientSecret = process.env.DISCORD_CLIENT_SECRET;
const cookieSecret = process.env.COOKIE_SECRET || generators.random();

const secureCookieConfig = {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    signed: true,
};

app.use(cookieParser(cookieSecret));
app.use(express.urlencoded({ extended: true }));

async function main() {
    try {
        const discordIssuer = new Issuer({
            issuer: 'https://discord.com',
            authorization_endpoint: 'https://discord.com/api/oauth2/authorize',
            token_endpoint: 'https://discord.com/api/oauth2/token',
            userinfo_endpoint: 'https://discord.com/api/v10/users/@me',
            jwks_uri: 'https://discord.com/.well-known/jwks.json',
        });

        const discordClient = new discordIssuer.Client({
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uris: ["https://testing45.onrender.com/oauth/discord-callback"],
            response_types: ["code"],
            scope: "identify",
        });

        custom.clock_tolerance = 180;

        async function checkLoggedIn(req, res, next) {
            if (req.signedCookies.tokenSet) {
                // Handle token verification and refresh if necessary
                next();
            } else {
                res.redirect("/login");
            }
        }

        app.get("/", checkLoggedIn, (req, res) => {
            res.redirect("/home");
        });

        app.get("/login", (req, res) => {
            const state = generators.state();
            res
                .cookie("state", state, secureCookieConfig)
                .redirect(
                    discordClient.authorizationUrl({
                        scope: "identify",
                        state,
                    })
                );
        });

        app.get("/oauth/discord-callback", async (req, res) => {
            const params = discordClient.callbackParams(req);
            const state = req.signedCookies.state;

            console.log('State from cookies:', state); // Debugging line

            if (!state) {
                return res.status(400).send('State missing in cookies');
            }

            try {
                const tokenSet = await discordClient.callback(
                    "https://testing45.onrender.com/oauth/discord-callback",
                    params,
                    { state }
                );

                const discordUser = tokenSet.claims();
                const discordData = {
                    discordId: discordUser.sub,
                    discordUsername: discordUser.preferred_username,
                };

                await db.ref(`users/${discordData.discordId}`).set(discordData);

                res.cookie("discordData", discordData, secureCookieConfig);
                res.redirect("/home");
            } catch (error) {
                console.error('Error during Discord OAuth callback:', error);
                res.status(500).send('Error during Discord OAuth callback');
            }
        });

        app.get("/home", checkLoggedIn, (req, res) => {
            const discordData = req.signedCookies.discordData || {};
            res.send(`<html><body><h1>Welcome, ${discordData.discordUsername || 'User'}!</h1></body></html>`);
        });

        app.listen(port, () => {
            console.log(`Server is running on port: ${port}`);
        });
    } catch (error) {
        console.error('Error in main execution:', error);
        process.exit(1);
    }
}

main();
