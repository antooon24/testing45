import express from 'express';
import { Issuer, TokenSet, custom, generators } from 'openid-client';
import { getHomeHtml } from './getHomeHtml.js';
import cookieParser from 'cookie-parser';
import admin from 'firebase-admin';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFile } from 'fs/promises';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Decode the base64 encoded service account JSON
const serviceAccountBase64 = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
if (!serviceAccountBase64) {
    console.error('FIREBASE_SERVICE_ACCOUNT_KEY environment variable is not set.');
    process.exit(1);
}

let serviceAccountJson;
try {
    serviceAccountJson = Buffer.from(serviceAccountBase64, 'base64').toString('utf8');
} catch (error) {
    console.error('Error decoding FIREBASE_SERVICE_ACCOUNT_KEY:', error);
    process.exit(1);
}

let serviceAccount;
try {
    serviceAccount = JSON.parse(serviceAccountJson);
} catch (error) {
    console.error('Error parsing JSON for FIREBASE_SERVICE_ACCOUNT_KEY:', error);
    process.exit(1);
}

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
});

const db = admin.database();
const app = express();
const port = process.env.PORT || 3000; // Use PORT from environment or default to 3000
const clientId = process.env.ROBLOX_CLIENT_ID;
const clientSecret = process.env.ROBLOX_CLIENT_SECRET;

const cookieSecret = process.env.COOKIE_SECRET || generators.random();
const secureCookieConfig = {
    secure: process.env.NODE_ENV === 'production', // Set to true in production with HTTPS
    httpOnly: true,
    signed: true,
};

// Middleware to simplify interacting with cookies
app.use(cookieParser(cookieSecret));

// Middleware to parse data from HTML forms
app.use(express.urlencoded({ extended: true }));

async function main() {
    try {
        const issuer = await Issuer.discover(
            "https://apis.roblox.com/oauth/.well-known/openid-configuration"
        );

        const client = new issuer.Client({
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uris: ["https://testing45.onrender.com/oauth/callback"], // Ensure this is a string
            response_types: ["code"],
            scope: "openid profile",
            id_token_signed_response_alg: "ES256",
        });

        client[custom.clock_tolerance] = 180;

        // Middleware to ensure user is logged in, refreshes tokens if needed
        async function checkLoggedIn(req, res, next) {
            if (req.signedCookies.tokenSet) {
                let tokenSet = new TokenSet(req.signedCookies.tokenSet);

                if (tokenSet.expired()) {
                    tokenSet = await client.refresh(tokenSet);
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
            const nonce = generators.nonce();

            res
                .cookie("state", state, secureCookieConfig)
                .cookie("nonce", nonce, secureCookieConfig)
                .redirect(
                    client.authorizationUrl({
                        scope: client.scope,
                        state,
                        nonce,
                    })
                );
        });

        app.get("/logout", async (req, res) => {
            if (req.signedCookies.tokenSet) {
                await client.revoke(req.signedCookies.tokenSet.refresh_token);
            }

            res.clearCookie("tokenSet").redirect("/");
        });

        app.get("/oauth/callback", async (req, res) => {
            const params = client.callbackParams(req);
            const state = req.signedCookies.state;
            const nonce = req.signedCookies.nonce;

            if (!state || !nonce) {
                console.error('State or nonce missing in cookies');
                return res.status(400).send('State or nonce missing in cookies');
            }

            try {
                const tokenSet = await client.callback(
                    "https://testing45.onrender.com/oauth/callback",
                    params,
                    {
                        state,
                        nonce,
                    }
                );

                res
                    .cookie("tokenSet", tokenSet, secureCookieConfig)
                    .clearCookie("state")
                    .clearCookie("nonce")
                    .redirect("/home");

                // Save user data to Firebase
                const userClaims = tokenSet.claims();
                console.log('User Claims:', userClaims);

                await db.ref(`users/${userClaims.sub}`).set({
                    name: userClaims.name,
                    nickname: userClaims.preferred_username,
                    profile: userClaims.profile,
                    picture: userClaims.picture,
                });

            } catch (error) {
                console.error('Error handling OAuth callback:', error);
                res.status(500).send('Error handling OAuth callback');
            }
        });

        app.get("/home", checkLoggedIn, (req, res) => {
            const tokenSet = new TokenSet(req.signedCookies.tokenSet);
            res.send(getHomeHtml(tokenSet.claims()));
        });

        app.post("/message", checkLoggedIn, async (req, res) => {
            const message = req.body.message;
            const apiUrl = `https://apis.roblox.com/messaging-service/v1/universes/${req.body.universeId}/topics/${req.body.topic}`;

            try {
                const result = await client.requestResource(
                    apiUrl,
                    req.signedCookies.tokenSet.access_token,
                    {
                        method: "POST",
                        body: JSON.stringify({ message }),
                        headers: {
                            "Content-Type": "application/json",
                        },
                    }
                );
                console.log(result);
                res.sendStatus(result.statusCode);
            } catch (error) {
                console.error(error);
                res.sendStatus(500);
            }
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