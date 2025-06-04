const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');

const HOSTNAME = 'localhost';
const PORT = 3000;
const PFX_FILENAME = 'localhost.pfx';
const PFX_PASSWORD = 'changeit';

const pfxPath = path.join(__dirname, PFX_FILENAME);

if (!fs.existsSync(pfxPath)) {
    console.error(`Error: PFX file not found at ${pfxPath}`);
    process.exit(1);
}

const httpsOptions = {
    pfx: fs.readFileSync(pfxPath),
    passphrase: PFX_PASSWORD,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    ciphers: 'TLS_RSA_WITH_AES_256_GCM_SHA384'
};

const server = https.createServer(httpsOptions, (req, res) => {
    const clientTlsVersion = req.socket.getProtocol();
    console.log(`Request received: ${req.method} ${req.url}. Client TLS version: ${clientTlsVersion}`);

    if (req.url === '/hello') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Мартинюк Михайло КП-22');
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('404 Not Found');
    }
});

server.listen(PORT, HOSTNAME, () => {
    console.log(`Server running at https://${HOSTNAME}:${PORT}/`);
    console.log(`Path available: https://${HOSTNAME}:${PORT}/hello`);
});

server.on('error', (err) => {
    console.error('Server error:', err.message);
    process.exit(1);
});
