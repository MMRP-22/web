process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const express = require('express');
const cookieParser = require('cookie-parser');
const config = require('./config'); 
const path = require('node:path');
const https = require('https');
const fs = require('fs');
const WebSocket = require('ws');

const app = express();
const PORT = 3000;
const PFX_FILENAME = 'localhost.pfx';
const PFX_PASSWORD = 'changeit';
const pfxPath = path.join(__dirname, PFX_FILENAME);

const BINANCE_WS_URL_BTC = 'wss://stream.binance.com:9443/ws/btcusdt@trade';
const BINANCE_WS_URL_ETH = 'wss://stream.binance.com:9443/ws/ethusdt@trade';
const BINANCE_WS_URL_DOGE = 'wss://stream.binance.com:9443/ws/dogeusdt@trade';

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

let binanceWsBtc = null;
let binanceWsEth = null;
let binanceWsDoge = null;

function setupBinanceWebSocket(currencyPair) {
    let wsUrl;
    let currentBinanceWs;
    let updateBinanceWsRef;

    switch (currencyPair) {
        case 'BTCUSDT':
            wsUrl = BINANCE_WS_URL_BTC;
            currentBinanceWs = binanceWsBtc;
            updateBinanceWsRef = (ws) => { binanceWsBtc = ws; };
            break;
        case 'ETHUSDT':
            wsUrl = BINANCE_WS_URL_ETH;
            currentBinanceWs = binanceWsEth;
            updateBinanceWsRef = (ws) => { binanceWsEth = ws; };
            break;
        case 'DOGEUSDT':
            wsUrl = BINANCE_WS_URL_DOGE;
            currentBinanceWs = binanceWsDoge;
            updateBinanceWsRef = (ws) => { binanceWsDoge = ws; };
            break;
        default:
            console.error(`Unknown currency pair: ${currencyPair}`);
            return;
    }

    if (currentBinanceWs && (currentBinanceWs.readyState === WebSocket.OPEN || currentBinanceWs.readyState === WebSocket.CONNECTING)) {
        console.log(`Binance WebSocket for ${currencyPair} is already open or connecting.`);
        return currentBinanceWs;
    }

    console.log(`Connecting to Binance WebSocket for ${currencyPair}...`);
    currentBinanceWs = new WebSocket(wsUrl);
    updateBinanceWsRef(currentBinanceWs);

    currentBinanceWs.onopen = () => {
        console.log(`Connected to Binance WebSocket API for ${currencyPair}`);
    };

    currentBinanceWs.onmessage = message => {
        const dataWithPair = JSON.parse(message.data);
        dataWithPair.currencyPair = currencyPair;

        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(dataWithPair));
            }
        });
    };

    currentBinanceWs.onerror = error => {
        console.error(`Binance WebSocket Error for ${currencyPair}:`, error.message);
        if (currentBinanceWs) {
            currentBinanceWs.close();
        }
        updateBinanceWsRef(null);
    };

    currentBinanceWs.onclose = () => {
        console.log(`Disconnected from Binance WebSocket API for ${currencyPair}`);
        updateBinanceWsRef(null);
    };
    return currentBinanceWs;
}

function parseAccessTokenFromCookie(cookieHeader) {
    if (!cookieHeader) {
        return null;
    }
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
        const parts = cookie.trim().split('=');
        if (parts[0] === 'access_token') {
            return parts[1];
        }
    }
    return null;
}

async function validateAccessToken(accessToken) {
    if (!accessToken) {
        return false;
    }
    try {
        const userinfoUrl = `${config.openIdConnectEndpoint}/api/userinfo`;
        const userinfoResponse = await fetch(userinfoUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });
        return userinfoResponse.ok;
    } catch (error) {
        console.error("Error validating token during WebSocket connection:", error);
        return false;
    }
}



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
                    margin-bottom: 10px;
                }
                .user-info-section, .crypto-updates-section {
                    margin-top: 20px;
                    border: 1px solid #ccc;
                    padding: 15px;
                    border-radius: 5px;
                }
                .crypto-updates-section h2 {
                    margin-top: 0;
                }
                .crypto-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    font-size: 1.2em;
                    font-weight: bold;
                    margin-bottom: 5px;
                    padding: 5px 0;
                    border-bottom: 1px solid #eee;
                }
                .crypto-item:last-child {
                    border-bottom: none;
                }
                .crypto-item .symbol {
                    flex: 0 0 100px;
                }
                .crypto-item .price {
                    flex-grow: 1;
                    text-align: right;
                    color: #007bff;
                }
                .crypto-item .timestamp {
                    font-size: 0.7em;
                    color: #666;
                    margin-left: 10px;
                    white-space: nowrap;
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
                <button id="cryptoUpdatesBtn">Cryptocurrency Updates</button>
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
            <div class="crypto-updates-section" style="display: none;">
                <h2>Live Crypto Prices (from Binance)</h2>
                <div id="btcItem" class="crypto-item">
                    <span class="symbol">BTC/USDT:</span>
                    <span class="price">Loading...</span>
                    <span class="timestamp"></span>
                </div>
                <div id="ethItem" class="crypto-item">
                    <span class="symbol">ETH/USDT:</span>
                    <span class="price">Loading...</span>
                    <span class="timestamp"></span>
                </div>
                <div id="dogeItem" class="crypto-item">
                    <span class="symbol">DOGE/USDT:</span>
                    <span class="price">Loading...</span>
                    <span class="timestamp"></span>
                </div>
            </div>

            <script>
                const cryptoUpdatesBtn = document.getElementById('cryptoUpdatesBtn');
                const cryptoUpdatesSection = document.querySelector('.crypto-updates-section');
                
                const btcPriceSpan = document.querySelector('#btcItem .price');
                const btcTimestampSpan = document.querySelector('#btcItem .timestamp');
                
                const ethPriceSpan = document.querySelector('#ethItem .price');
                const ethTimestampSpan = document.querySelector('#ethItem .timestamp');
                
                const dogePriceSpan = document.querySelector('#dogeItem .price');
                const dogeTimestampSpan = document.querySelector('#dogeItem .timestamp');
                
                let wsCrypto = null; 

                if (cryptoUpdatesBtn) {
                    cryptoUpdatesBtn.addEventListener('click', () => {
                        if (wsCrypto && wsCrypto.readyState === WebSocket.OPEN) {
                            console.log("WebSocket for crypto already open.");
                            cryptoUpdatesSection.style.display = cryptoUpdatesSection.style.display === 'none' ? 'block' : 'none';
                            return;
                        }

                        cryptoUpdatesSection.style.display = 'block';

                        btcPriceSpan.textContent = 'Loading...';
                        ethPriceSpan.textContent = 'Loading...';
                        dogePriceSpan.textContent = 'Loading...';
                        btcTimestampSpan.textContent = '';
                        ethTimestampSpan.textContent = '';
                        dogeTimestampSpan.textContent = '';

                        wsCrypto = new WebSocket('wss://localhost:' + ${PORT}); 

                        wsCrypto.onopen = () => {
                            console.log('Connected to local WebSocket for crypto updates.');
                        };

                        wsCrypto.onmessage = event => {
                            try {
                                const data = JSON.parse(event.data);
                                if (data.s && typeof data.p !== 'undefined' && data.E) { 
                                    const symbol = data.s; 
                                    const price = parseFloat(data.p); 
                                    const timestamp = new Date(data.E).toLocaleTimeString(); 

                                    if (symbol === 'BTCUSDT') {
                                        btcPriceSpan.textContent = \`\${ price.toFixed(2) } \`;
                                        btcTimestampSpan.textContent = \`\${ timestamp }\`;
                                    } else if (symbol === 'ETHUSDT') {
                                        ethPriceSpan.textContent = \`\${ price.toFixed(2) } \`;
                                        ethTimestampSpan.textContent = \`\${ timestamp }\`;
                                    } else if (symbol === 'DOGEUSDT') {
                                        dogePriceSpan.textContent = \`\${ price.toFixed(5) }\`; 
                                        dogeTimestampSpan.textContent = \`\${ timestamp }\`;
                                    }
                                }
                            } catch (e) {
                                console.error('Error parsing crypto update:', e);
                            }
                        };

                        wsCrypto.onclose = (event) => { 
                            console.log('Disconnected from local WebSocket for crypto updates.', event);
                            let message = 'Disconnected';
                            if (event.code === 1008) { 
                                message = 'Authorization required or expired. Please login again.';
                            }
                            btcPriceSpan.textContent = message;
                            ethPriceSpan.textContent = message;
                            dogePriceSpan.textContent = message;
                            btcTimestampSpan.textContent = '';
                            ethTimestampSpan.textContent = '';
                            dogeTimestampSpan.textContent = '';
                        };

                        wsCrypto.onerror = (error) => {
                            console.error('Local WebSocket error for crypto updates:', error);
                            btcPriceSpan.textContent = 'Error';
                            ethPriceSpan.textContent = 'Error';
                            dogePriceSpan.textContent = 'Error';
                            btcTimestampSpan.textContent = '';
                            ethTimestampSpan.textContent = '';
                            dogeTimestampSpan.textContent = '';
                        };
                    });
                }
            </script>
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
    if (binanceWsBtc) {
        binanceWsBtc.close();
        binanceWsBtc = null;
    }
    if (binanceWsEth) {
        binanceWsEth.close();
        binanceWsEth = null;
    }
    if (binanceWsDoge) {
        binanceWsDoge.close();
        binanceWsDoge = null;
    }
    res.redirect('/');
});

const httpsOptions = {
    pfx: fs.readFileSync(pfxPath),
    passphrase: PFX_PASSWORD,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    ciphers: 'TLS_RSA_WITH_AES_256_GCM_SHA384'
};

const server = https.createServer(httpsOptions, app);

const wss = new WebSocket.Server({ server });

wss.on('connection', async (ws, request) => { 
    console.log('Client attempting to connect to WebSocket server...');

    const cookieHeader = request.headers.cookie;
    console.log(`WebSocket: Received cookie header: ${cookieHeader ? cookieHeader.split(';').map(c => c.trim().split('=')[0]).join(', ') : 'None'}`);
    const accessToken = parseAccessTokenFromCookie(cookieHeader);

    if (!accessToken) {
        console.log('WebSocket connection denied: No access token found in cookies.');
        ws.close(1008, 'Unauthorized: No token provided. Please log in.'); 
        return; 
    }

    console.log('WebSocket: Access token found. Initiating validation...');
    const isValid = await validateAccessToken(accessToken);

    if (!isValid) {
        console.log('WebSocket connection denied: Invalid or expired access token.');
        ws.close(1008, 'Unauthorized: Invalid or expired token. Please log in again.');
        return; 
    }


    console.log('WebSocket connection authorized for cryptocurrency updates.');

    setupBinanceWebSocket('BTCUSDT');
    setupBinanceWebSocket('ETHUSDT');
    setupBinanceWebSocket('DOGEUSDT');

    ws.on('close', () => {
        console.log('Client disconnected from our secure WebSocket server');
    });

    ws.on('error', error => {
        console.error('Our WebSocket server error:', error.message);
    });
});

server.listen(PORT, () => {
    console.log(`HTTPS Server running on https://localhost:${PORT}`);
    console.log(`WebSocket server for clients running on wss://localhost:${PORT}`);
});
