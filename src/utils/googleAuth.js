const { google } = require('googleapis');
const { OAuth2Client } = require('google-auth-library');
const { decrypt } = require('./encryption');


// export async function authoriseGoogleDrive(credentials:any) {
//     const {client_id, client_secret,redirect_uris} = credentials.installed || credentials.web
//     const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);

//     // Check if we have previously stored a token.
//     const token = await getTokenFromDatabase(credentials);

//     if (token){
//         oAuth2Client.setCredentials(token)
//     }else{
//         const authUrl = oAuth2Client.generateAuthUrl({
//             access_type: 'offline',
//             scope: ['https://www.googleapis.com/auth/drive'],
//         });
//         console.log('Authorize this app by visiting this url:', authUrl);
//         const code = 'authorization_code'; // Replace with the actual code
//         const token = await oAuth2Client.getToken(code);
//         oAuth2Client.setCredentials(token.tokens);
//         await saveTokenToDatabase(credentials, token.tokens);
//     }

//     return oAuth2Client
// }

// Helper to initialize the Google Drive API client
 const setupGoogleDriveClient = (credential, tokens) => {
    const oAuth2Client = new google.auth.OAuth2(
        credential.client_id,
        credential.client_secret,
        credential.redirect_uris[0]
    );
    oAuth2Client.setCredentials(tokens);

    return google.drive({ version: 'v3', auth: oAuth2Client });
};



module.exports = { setupGoogleDriveClient }