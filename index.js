import express from 'express';
import { Issuer } from 'openid-client';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

const clientId = process.env.DISCORD_CLIENT_ID;
const clientSecret = process.env.DISCORD_CLIENT_SECRET;
const redirectUri = 'https://testing45.onrender.com/oauth/discord-callback/';
const cookieSecret = process.env.COOKIE_SECRET || 'random_secret_string';
const secureCookieConfig = {
    secure: process.env.NODE_ENV === 'production',
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
            scope: 'identify',
        });

        async function checkLoggedIn(req, res, next) {
            if (req.signedCookies.tokenSet) {
                let tokenSet;

                // Debug: Log the cookie value to understand its format
                console.log('TokenSet cookie:', req.signedCookies.tokenSet);

                try {
                    // Attempt to parse the tokenSet cookie value
                    tokenSet = JSON.parse(req.signedCookies.tokenSet);

                    // Debug: Log the parsed tokenSet
                    console.log('Parsed tokenSet:', tokenSet);
                } catch (parseError) {
                    console.error('Error parsing tokenSet:', parseError);
                    return res.status(400).send('Invalid token data');
                }

                // Check token expiry and refresh if needed
                if (new Date().getTime() / 1000 >= tokenSet.expires_at) {
                    try {
                        const refreshedTokenSet = await discordClient.refresh(tokenSet.refresh_token);
                        res.cookie('tokenSet', JSON.stringify(refreshedTokenSet), secureCookieConfig);
                        tokenSet = refreshedTokenSet; // Update tokenSet after refresh
                    } catch (refreshError) {
                        console.error('Error refreshing token:', refreshError);
                        return res.status(500).send('Error refreshing token');
                    }
                }

                req.tokenSet = tokenSet; // Attach tokenSet to request object
                next();
            } else {
                res.redirect('/login');
            }
        }

        app.get('/', checkLoggedIn, (req, res) => {
            res.redirect('/home');
        });

        app.get('/login', (req, res) => {
            const state = generateState();
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
                return res.status(400).send('State missing in cookies');
            }

            try {
                const tokenSet = await discordClient.callback(redirectUri, params, { state });

                // Store tokenSet in cookies
                res.cookie('tokenSet', JSON.stringify(tokenSet), secureCookieConfig);

                // Optionally store or use tokenSet here

                res.redirect('/home');
            } catch (error) {
                console.error('Error during Discord OAuth callback:', error);
                res.status(500).send('Error during Discord OAuth callback');
            }
        });

        app.get('/home', checkLoggedIn, (req, res) => {
            const tokenSet = req.tokenSet || {};
            const user = tokenSet.claims();
            res.send(`Welcome ${user.username || 'Guest'}`);
        });

        app.listen(port, () => {
            console.log(`Server is running on port: ${port}`);
        });
    } catch (error) {
        console.error('Error in main execution:', error);
        process.exit(1);
    }
}

// Utility function to generate a state parameter
function generateState() {
    return Math.random().toString(36).substr(2, 10); // Adjust length as needed
}

main();
