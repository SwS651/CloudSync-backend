const fetch = require('node-fetch');
const Account = require('../models/account'); // Import the Account schema
const { google } = require('googleapis');
const { decrypt, encrypt } = require('./encryption');
// Check if token is expired
const isTokenExpired = (tokens) => {
    const parsedTokens = JSON.parse(tokens);
    const now = new Date();
    return new Date(parsedTokens.expires_at) <= now;
};

// Refresh Google Drive token
const refreshGoogleToken = async (refreshToken,credential) => {

    
    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: credential.client_id,
            client_secret: credential.client_secret,
            refresh_token: refreshToken,
            grant_type: 'refresh_token',
        }),
    });

    const data = await response.json();
    if (!data.access_token) {
        throw new Error('Failed to refresh Google token');
    }

    return {
        access_Token: data.access_token,
        refresh_Token: data.refresh_token || refreshToken,
        expires_date:data.expires_in,
        expiresAt: new Date(Date.now() + data.expires_in * 1000).toISOString(),
    };
};

// Refresh Dropbox token
const refreshDropboxToken = async (refreshToken) => {
    const response = await fetch('https://api.dropbox.com/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            client_id: process.env.DROPBOX_CLIENT_ID,
            client_secret: process.env.DROPBOX_CLIENT_SECRET,
            refresh_token: refreshToken,
            grant_type: 'refresh_token',
        }),
    });

    const data = await response.json();
    if (!data.access_token) {
        throw new Error('Failed to refresh Dropbox token');
    }

    return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token || refreshToken,
        expiresAt: new Date(Date.now() + data.expires_in * 1000).toISOString(),
    };
};

// Update account tokens
const updateAccountTokens = async (accountId, tokens, isAuthorized = true) => {

    await Account.findByIdAndUpdate(accountId, {
        tokens: encrypt(JSON.stringify(tokens)),
        isAuthorized,
        updatedAt: Date.now(),
    });
};


module.exports = {
    isTokenExpired,
    refreshGoogleToken,
    refreshDropboxToken,
    updateAccountTokens
}