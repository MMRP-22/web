process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const express = require('express');
const cookieParser = require('cookie-parser');
const config = require('./config');

const app = express();
const PORT = 3000;

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.get('/', async (req, res) => {
    const accessToken = req.cookies.access_token;
    let userInfoHtml = '';
    let action = req.query.action; 

    if (accessToken && action === 'getUserInfo') {
        try {
            const userinfoUrl = `${config.openIdConnectEndpoint}/api/userinfo`;
            const userinfoResponse = await fetch(userinfoUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });

            if (!userinfoResponse.ok) {
                const errorText = await userinfoResponse.text();
                console.error(`Failed to fetch UserInfo: ${userinfoResponse.status} - ${errorText}`);
                res.clearCookie('access_token');
                return res.redirect('/login');
            }

            const userInfo = await userinfoResponse.json();
            console.log("Full User Info:", userInfo); 

            userInfoHtml = '<h2>User Information:</h2>';
            userInfoHtml += '<ul>';
            userInfoHtml += `<li><strong>User ID (sub):</strong> ${userInfo.sub || 'N/A'}</li>`;
            userInfoHtml += `<li><strong>Username (name):</strong> ${userInfo.name || 'N/A'}</li>`;
            userInfoHtml += '</ul>';

        } catch (error) {
            console.error("Error fetching UserInfo:", error);
            userInfoHtml = '<p style="color: red;">Error fetching user information.</p>';
        }
    }

    let pageHtml = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OIDC Client</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .button-container button {
                    padding: 10px 15px;
                    margin-right: 10px;
                    font-size: 16px;
                    cursor: pointer;
                }
                .user-info-section {
                    margin-top: 20px;
                    border: 1px solid #ccc;
                    padding: 15px;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <h1>OIDC Client Application</h1>
            <div class="button-container">
    `;

    if (accessToken) {
        pageHtml += `
                <button onclick="window.location.href='/logout'">Logout</button>
                <button onclick="window.location.href='/?action=getUserInfo'">Get User Info</button>
        `;
    } else {
        pageHtml += `
                <button onclick="window.location.href='/login'">Login</button>
        `;
    }

    pageHtml += `
            </div>
            <div class="user-info-section">
                ${userInfoHtml}
            </div>
        </body>
        </html>
    `;

    res.send(pageHtml);
});

app.get('/login', (req, res) => {
    console.log("Login requested");

    const authorizeUrl = new URL(`${config.openIdConnectEndpoint}/login/oauth/authorize`);
    authorizeUrl.searchParams.append("client_id", config.openIdConnectClientId);
    authorizeUrl.searchParams.append("response_type", "code");
    authorizeUrl.searchParams.append("redirect_uri", config.redirectUri);
    authorizeUrl.searchParams.append("scope", "openid profile email");

    console.log(`Redirecting to: ${authorizeUrl.toString()}`);
    res.redirect(authorizeUrl.toString());
});

app.get('/callback', async (req, res) => {
    const code = req.query.code;
    console.log(`Got code: ${code}`);

    if (!code) {
        return res.status(400).send('Error: Authorization code not received.');
    }

    try {
        const tokenUrl = `${config.openIdConnectEndpoint}/api/login/oauth/access_token`;

        const formData = new URLSearchParams();
        formData.append("grant_type", "authorization_code");
        formData.append("code", code);
        formData.append("client_id", config.openIdConnectClientId);
        formData.append("client_secret", config.openIdConnectClientSecret);
        formData.append("redirect_uri", config.redirectUri);

        const response = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formData
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`Token exchange failed: ${response.status} - ${errorText}`);
            return res.status(response.status).send(`Token exchange failed: ${errorText}`);
        }

        const tokenResponse = await response.json();
        const accessToken = tokenResponse.access_token;
        console.log(`Received access token: ${accessToken}`); 

        res.cookie('access_token', accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
            path: '/'
        });

        res.redirect("/");

    } catch (error) {
        console.error("Error during token exchange:", error);
        res.status(500).send("Internal Server Error during token exchange.");
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('access_token');
    res.redirect('/');
});

const https = require('https');
const fs = require('fs');

const sslOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};

https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`HTTPS Server running on https://localhost:${PORT}`);
});