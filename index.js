import express from 'express';
import { Issuer, TokenSet, custom, generators } from 'openid-client';
import { getHomeHtml } from './getHomeHtml.js';
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
        // Discover Discord issuer
        const discordIssuer = await Issuer.discover(
            "https://discord.com/.well-known/openid-configuration"
        );

        // Create Discord client
        const discordClient = new discordIssuer.Client({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            redirect_uris: ["https://testing45.onrender.com/oauth/discord-callback"],
            response_types: ["code"],
            scope: "identify",
        });

        custom.clock_tolerance = 180;

        // Middleware to check if the user is logged in
        async function checkLoggedIn(req, res, next) {
            if (req.signedCookies.tokenSet) {
                let tokenSet = new TokenSet(req.signedCookies.tokenSet);

                if (tokenSet.expired()) {
                    tokenSet = await discordClient.refresh(tokenSet);
                    res.cookie("tokenSet", tokenSet, secureCookieConfig);
                }

                next();
            } else {
                res.redirect("/login");
            }
        }

        // Routes
        app.get("/", checkLoggedIn, (req, res) => {
            res.redirect("/home");
        });

        app.get("/login", (req, res) => {
            const state = generators.state();
            res
                .cookie("state", state, secureCookieConfig)
                .redirect(
                    discordClient.authorizationUrl({
                        scope: discordClient.scope,
                        state,
                    })
                );
        });

        app.get("/oauth/discord-callback", async (req, res) => {
            const params = discordClient.callbackParams(req);
            const state = req.signedCookies.state;

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

                // Store user data in Firebase
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
            res.send(getHomeHtml(discordData));
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
