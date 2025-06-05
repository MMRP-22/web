const config = {
    openIdConnectEndpoint: process.env.OIDC_ENDPOINT || "https://localhost:10443",
    openIdConnectClientId: process.env.OIDC_CLIENT_ID || "dae296c275681473b57c",
    openIdConnectClientSecret: process.env.OIDC_CLIENT_SECRET || "c33a0b77858578dccd8f7622aff038ea352d2933",
    redirectUri: process.env.OIDC_REDIRECT_URI || "https://localhost:3000/callback"
};

module.exports = config;
