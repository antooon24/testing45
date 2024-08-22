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
const clientId = process.env.ROBLOX_CLIENT_ID;
const clientSecret = process.env.ROBLOX_CLIENT_SECRET;

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
        const robloxIssuer = await Issuer.discover(
            "https://apis.roblox.com/oauth/.well-known/openid-configuration"
        );
        const discordIssuer = await Issuer.discover(
            "https://discord.com/api/oauth2/authorize"
        );

        const robloxClient = new robloxIssuer.Client({
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uris: ["https://testing45.onrender.com/oauth/roblox-callback"],
            response_types: ["code"],
            scope: "openid profile",
            id_token_signed_response_alg: "ES256",
        });

        const discordClient = new discordIssuer.Client({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            redirect_uris: ["https://testing45.onrender.com/oauth/discord-callback"],
            response_types: ["code"],
            scope: "identify",
        });

        client[custom.clock_tolerance] = 180;

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
                    robloxClient.authorizationUrl({
                        scope: robloxClient.scope,
                        state,
                        nonce,
                    })
                );
        });

        app.get("/oauth/roblox-callback", async (req, res) => {
            const params = robloxClient.callbackParams(req);
            const state = req.signedCookies.state;
            const nonce = req.signedCookies.nonce;

            if (!state || !nonce) {
                return res.status(400).send('State or nonce missing in cookies');
            }

            try {
                const tokenSet = await robloxClient.callback(
                    "https://testing45.onrender.com/oauth/roblox-callback",
                    params,
                    { state, nonce }
                );

                const userClaims = tokenSet.claims();
                const robloxData = {
                    robloxId: userClaims.sub,
                    robloxName: userClaims.name,
                    robloxProfile: userClaims.profile,
                    robloxPicture: userClaims.picture || null,  // Handle missing picture
                };

                res.cookie("robloxData", robloxData, secureCookieConfig);
                res.redirect("/oauth/discord-login");
            } catch (error) {
                console.error('Error during Roblox OAuth callback:', error);
                res.status(500).send('Error during Roblox OAuth callback');
            }
        });

        app.get("/oauth/discord-login", (req, res) => {
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

                const robloxData = req.signedCookies.robloxData;

                // Store combined data in Firebase
                await db.ref(`users/${robloxData.robloxId}`).set({
                    ...robloxData,
                    ...discordData,
                });

                res.clearCookie("robloxData");
                res.redirect("/home");
            } catch (error) {
                console.error('Error during Discord OAuth callback:', error);
                res.status(500).send('Error during Discord OAuth callback');
            }
        });

        app.get("/home", checkLoggedIn, (req, res) => {
            const robloxData = req.signedCookies.robloxData || {};
            const discordData = req.signedCookies.discordData || {};
            res.send(getHomeHtml({ ...robloxData, ...discordData }));
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
	