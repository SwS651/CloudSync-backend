const { Request, Response } = require('express');
const { google } = require('googleapis');
const mongoose = require('mongoose');
const fs = require('fs');
const archiver = require('archiver'); 
const axios = require('axios')

const  Credential  = require('../../models/credential');

const { decrypt, encrypt } = require('../../utils/encryption');
const url = require('url');
const Account = require('../../models/Account');
const { OAuth2Client } = require('google-auth-library');

const { getCredentialById, getCredentialByProvider, defaultCredential} = require(  '../credentialsController');
const  {findCredentialByCloudAPI}  = require(  '../credentialsController');
const { findAccountById } = require( '../accountsController');

const { createSuccessResponse,createErrorResponse} = require('../../utils/setupResponse')
const { formatBytes } = require( '../../utils/bytesConverter');
const { setupGoogleDriveClient } = require( '../../utils/googleAuth');

//LV 2 Methods
// Utility function to create an OAuth2 client
const createOAuth2Client = (credentialData) => {
    const { client_id, client_secret, redirect_uris } = credentialData;
    if (!client_id || !client_secret || !redirect_uris || !redirect_uris.length) {
        throw new Error('Invalid credential data');
    }
    return new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);
};

// Function to generate an auth URL
const generateAuthUrl = (oAuth2Client, state) => {
    return oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/drive.readonly',
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/drive.metadata.readonly',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ],
        include_granted_scopes: true,
        state: JSON.stringify(state)
    });
};



//Configuration
const initialGoogleDrive = async(aid) =>{
    try {
        
        let account = await Account.findById(aid) || null
        if(!account) return {status:false,message:"Account not found"}
        

        let c = await Credential.findById(account.credentialId) || null
        if(!c) return {status:false,message:"Credential not found"}
        c.credential = decrypt(c.credential)
        c = JSON.stringify(c)

        const credential = JSON.parse(c)
        credential.credential = JSON.parse(credential.credential)

        let {client_id,client_secret,redirect_uris} = credential.credential.installed || credential.credential.web
        // console.log('credential:',{client_id,client_secret,redirect_uris})
        const oAuth2Client = new google.auth.OAuth2({ 
            client_id: client_id, 
            client_secret: client_secret, 
            redirect_uris:redirect_uris 
        });
        // let newTokens = await refreshGoogleToken(JSON.parse(decrypt(account.tokens)),oAuth2Client)
        // // account.tokens = encrypt(JSON.parse(newTokens))
        // // await account.save()
        // console.log("new Access token: ",newTokens)
        account.tokens = decrypt(account.tokens)
        
        oAuth2Client.setCredentials(JSON.parse(account.tokens))
        // const oAuth2Clientv2 = google.oauth2({ version: 'v2' ,auth:oAuth2Client});
        const oAuth2Clientv3 = google.drive({version:'v3',auth:oAuth2Client})


        return {status:true,account,credential,oAuth2Client,oAuth2Clientv3}
    } catch (error) {
        console.log("Error: ",error.message)
        return {status:false,message:error.message}
    }
}


// Function to initiate Google Authentication
const initiateGoogleAuth = async (req, res) => {

    try {
        const credential = await findCredentialByCloudAPI('google')
        if(!credential)
            return res.status(500).json({ message: 'Invalid credential data' }); 
        
        const oAuth2Client = createOAuth2Client(credential);
        console.log("OAuth2 client created")

        const userId    = req.body.userId || req.query.userId;
        const authUrl   = generateAuthUrl(oAuth2Client,{userId})
        console.log("Auth URL generated:"), 

        res.status(200).json({
            success: true,
            message: "Auth URL generated successfully",
            authUrl
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message:`Error initiating Google Auth: ${error.message}` 
        });
    }
};

//Set google credential
const setGoogleCredential = async(req,res)=>{
   try{
        const { credential, provider, type } = req.body;
        let q = await Credential.findOne({provider:provider,type:type})
        q = !q? await Credential.create(defaultCredential(provider,type)): q
    
        q.credential = encrypt(credential)
        q.metadata = {status:true,remark:"Inserted"}
        await q.save()

        if(q.type==="cloudAPI" && q.provider==="google")
            await revokeAccounts(q._id)


        return res.status(200).json({success:true,message:"Set credential successfully"});
    }catch(error){

        return res.status(500).json({success:true,message:`Failed to upload Google Credential: ${error.message}`});
    }
}

//New Generate Auth URL
const generateAuthLink = async(uid)=>{

    // Fetch associated credentials
    const credential = await Credential.findOne({provider:"google",type:"cloudAPI"});
    if (!credential) {
        return res.status(404).send({ status: false, message: "Credential not found" });
    }

    //Decrypt client credentials
    const decryptedCredential = JSON.parse(decrypt(credential.credential));
    const { client_id, client_secret,redirect_uris } = decryptedCredential.web || decryptedCredential.installed;
    console.log("client: ",client_id)
    const oAuth2Client = new google.auth.OAuth2(
        client_id, 
        client_secret, 
        redirect_uris
    );

    let provider = "google"
    const authUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/drive.readonly',
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/drive.metadata.readonly',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ],
        prompt:"select_account",
        include_granted_scopes: true,
        state: JSON.stringify({uid,provider})
    });
    return {authUrl}
    
}

const oAuthCallBack = async(req,res)=>{
    const { code, state: encodedState, error } = url.parse(req.url, true).query;
    
    if (error) {
        console.error("OAuth error:", error);
        return res.redirect(
            `http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(error)}`
        );
    }
    
    try {
        const {uid,provider} = JSON.parse(encodedState);
         // Fetch associated credentials
        const credential = await Credential.findOne({provider:"google",type:"cloudAPI"});
        if (!credential) {
            return res.status(404).send({ status: false, message: "Credential not found" });
        }

        //Decrypt client credentials
        const decryptedCredential = JSON.parse(decrypt(credential.credential));
        const { client_id, client_secret,redirect_uris } = decryptedCredential.web || decryptedCredential.installed;

        // Exchange code for tokens
        let tokenResponse = await axios.post("https://oauth2.googleapis.com/token", {
            code,
            client_id:client_id,
            client_secret: client_secret,
            redirect_uri: redirect_uris[0],
            grant_type: "authorization_code",
        },
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );
        
        // Get user info
        let userInfo = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
            headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` },
        });
        let email = userInfo.data.email;


        // Check if account exists
        const existingAccount = await Account.findOne({ uid, email, provider });
        if (existingAccount) {
            return res.redirect(
                `http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(
                    "Account already connected"
                )}`
            );
        }

        // Save the tokens to the database
        await Account.create({
            credentialId: credential._id,
            uid,
            provider,
            tokens: encrypt(JSON.stringify(tokenResponse.data)),
            email,
            isActive: true,isPublic: true,isAuthorized: true
        });
        res.redirect('http://localhost:5173/oauth-success?status=success');
    } catch (error) {
        console.error("Error during OAuth callback:", error.message);
        res.redirect(`http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(error.message)}`);
    }

}


// Function to reauthorize Google Authentication
const reauthoriseGoogleAuth = async (req, res) => {
    try {
        const { token } = req.body;
        const account = await Account.findOne({ _id: token });
        if (!account) return res.status(404).json({success: false,message: 'Account not found'});
        

        const credential = await findCredentialByCloudAPI('google');
        if (!credential) return res.status(404).json({success: false, message: 'Credential not found'});
       
        const oAuth2Client  = createOAuth2Client(credential)
        const authUrl       = generateAuthUrl(oAuth2Client,{token:account._id})

        return res.status(200).json({success: true,message: "Get auth URL successful",authUrl});
    } catch (error) {
        return res.status(500).json({success: false,message: `An error occurred during re-authorise account. Error: ${error.message}`});
    }
};

// Function for OAuth2 Callback
const oauth2Callback = async (req, res) => {
    try {
        const { code, state: encodedState, error } = url.parse(req.url, true).query;
        if (error) return res.status(400).json({ success: false, message: `Error: ${error}` });

       
   
        const q = await Credential.findOne({provider:'google'})
        if (!q) return res.status(404).json({success: false, message: 'Credential not found'});
        const credential = JSON.parse(decrypt(q.credential))
        
        const oAuth2Client = createOAuth2Client(credential.web || credential.installed)
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);

        // Fetch user information using the OAuth2 client
        const oauth2 = google.oauth2({ auth: oAuth2Client, version: 'v2' });
        const { data: userInfo } = await oauth2.userinfo.get();
        
        // Parse the state parameter to get the userId
        const state = JSON.parse(encodedState);
        if (!state.token) {
            const existingAccount = await Account.findOne({ credentialId: q._id, email: userInfo.email });
            if (existingAccount) {
                console.log('Account already exists, refusing to create a new one');
                return res.redirect(`http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent("Account already exists")}`);
            }

            // Save the tokens to the database
            await Account.create({
                credentialId: q._id,
                uid: state.userId,
                provider:"google",
                tokens: encrypt(JSON.stringify(tokens)),
                email: userInfo.email,
                isActive: true,
                isPublic: true,
                isAuthorized: true
            });
        } else {
            const account = await Account.findOne({_id:state.token});
            if (!account) return res.status(404).json({success: false, message: 'Account  not found'});
            
            account.tokens = encrypt(JSON.stringify(tokens));
            await account.save();
        }

        // Redirect to the frontend with a success message or any required data
        res.redirect('http://localhost:5173/oauth-success?status=success');
    } catch (error) {
        console.log(error.message)
        res.redirect(`http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(error.message)}`);
    }
};

// const fetchGooglefolder = async (fid = "root", aid) => {
//     try {
//         // Step 1: Get account and credential
//         const accountResult = await Account.findById(aid);
//         if (!accountResult) return createErrorResponse("Accounts not found");

//         const credentialResult = await Credential.findById(accountResult.credentialId);
//         if (!credentialResult) return createErrorResponse("Credential not found");

//         // Step 2: Set up OAuth client and Google Drive API
//         let token = JSON.parse(decrypt(accountResult.tokens))
//         let decryptedCredential = JSON.parse(decrypt(credentialResult.credential))
//         const { client_id, client_secret, redirect_uris } = decryptedCredential.installed || decryptedCredential.web;

//         const drive = setupGoogleDriveClient({ client_id, client_secret, redirect_uris }, token);

//         // Step 3: Fetch files in the folder
//         const response = await drive.files.list({
//             q: `'${fid}' in parents`,
//             fields: 'files(id, name, mimeType, size, createdTime, modifiedTime, parents)'
//         });
//         const files = response.data.files || [];

//         if (!files?.length) return createErrorResponse("No files found");

//         return {
//             success: true,
//             message: "",
//             data: files
//         };
//     } catch (error) {
//         return {
//             success: false,
//             message: `An error occurred while listing files. Error: ${error.message}`,
//             data: {}
//         };
//     }
// };

const fetchGooglefolder = async (fid = "root", aid) => {
    try {
        // Step 1: Get account and credential
        const  {account,credential,oAuth2Clientv3} = await initialGoogleDrive(aid)
        // Step 2: Fetch files in the folder
        const response = await oAuth2Clientv3.files.list({
            q: `'${fid}' in parents`,
            fields: 'files(id, name, mimeType, size, createdTime, modifiedTime, parents)'
        });
 
        // const files = response.data.files || [];
        const files = response.data.files.map(file=>({
            id:file.id,
            name: file.name,
            type: file.mimeType,
            path: file.parents[0],
            size: file.size || 0,
            createdTime: file.createdTime || "-",
            modifiedTime: file.modifiedTime|| "-",
            source: 'google',
        } 
        ))

        // if (!files?.length) return createErrorResponse("");

        return {
            success: true,
            message: "No files found",
            data: files
        };
    } catch (error) {
        return {
            success: false,
            message: `An error occurred while listing files. Error: ${error.message}`,
            data: {}
        };
    }
};

const fetchAllGoogleDriveFiles = async (uid) => {
    try {
        const accounts = await Account.find({
            $or: [
                { isPublic: true, isAuthorized: true, isActive: true },
                { uid }
            ]
        }).populate({ path: 'credentialId', select: 'provider' });

        if (!accounts) return createErrorResponse('Accounts not found');

        const data = await Promise.all(accounts.map(async (account) => {
            if (!(account.credentialId instanceof mongoose.Types.ObjectId)) {
                const credentialResult = await getCredentialByProvider(account.credentialId.provider);
                if (!credentialResult.success) return createErrorResponse('Credential not found');

                const token = JSON.parse(decrypt(account.tokens));
                const drive = setupGoogleDriveClient(credentialResult.data, token);
                const filesResult = await fetchGooglefolder("root", account._id);
                if (!filesResult.success) return filesResult.data;

                return { files: filesResult.data };
            }
        }));

        return createSuccessResponse(data, '');
    } catch (error) {
        return createErrorResponse(`An error occurred while listing files for all accounts. Error: ${error.message}`);
    }
};

const listAllDriveWithFiles = async (uid) => {
    try {
        const accounts = await Account.find({
            $or: [
                { isPublic: true, isActive: true, isAuthorized: true,provider:"google" },
                { uid:uid, isActive: true, isAuthorized: true,provider:"google" }
            ]
        }).populate({ path: 'credentialId', select: 'provider' });

      
        if (!accounts) return createErrorResponse('Accounts not found');

        const data = await Promise.all(accounts.map(async (account) => {
            if (!(account.credentialId instanceof mongoose.Types.ObjectId)) {
                console.log(account.email)
                const usageResult = await googleDriveStatus(account._id);
                const filesResult = await fetchGooglefolder("root", account._id);

                const drive = {
                    id: account._id,
                    email: account.email,
                    provider: account.credentialId.provider,
                    isAuthorized: account.isAuthorized,
                    isActive: account.isActive,
                    isPublic: account.isPublic,
                    usage: usageResult.data
                };

                return {
                    drive,
                    files: filesResult.data
                };
            }
        }));

        return createSuccessResponse(data, '');
    } catch (error) {
        return createErrorResponse(`An error occurred while listing files for all accounts. Error: ${error.message}`);
    }
}


//  const downloadGooglDriveFile = async(req,res) =>{
//     let {fid,aid} = req.body
//     try {
//         const {account,credential,oAuth2Clientv3:drive} = await initialGoogleDrive(aid)
//         // const { 
//         //     success: accountSuccess, 
//         //     data: account, 
//         //     message: accountMessage 
//         // } = await findAccountById(aid);

//         // const { 
//         //     success: credentialSuccess, 
//         //     data: credential, 
//         //     message: credentialMessage 
//         // } = await getCredentialById(account.credentialId);

//         // if (!credentialSuccess) 
//         // return createErrorResponse("Credential not found", credentialMessage);

//         // // Step 2: Set up OAuth client and Google Drive API
//         // const drive = setupGoogleDriveClient(credential, account.tokens);
        
//         // Step 3: Get file metadata to determine if it's a regular file or Google Workspace file
//         const { data: fileMetadata } = await drive.files.get({
//             fileId: fid,
//             fields: 'id, name, mimeType',
//         });

//         const fileName = fileMetadata.name;
//         const mimeType = fileMetadata.mimeType;
//          // Step 4: Fetch the file content as a stream (proxy request)
//          const fileStream = await drive.files.get(
//             { fileId: fid, alt: 'media' },
//             { responseType: 'stream' }
//         );  

//         // Step 5: Set the appropriate headers and pipe the content to the response
//         res.setHeader('Content-Type', mimeType || 'application/octet-stream');
//         res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
//         fileStream.data.pipe(res);

//     } catch (error) {
//         console.error('Failed to download file:', error.message);
//         return res.status(500).send({ error: `An error occurred while downloading the file, error: ${error.message}`});
//     }
   
        
// }

const uploadToGoogleDrive = async(aid,folderId,file)=>{
    try {
        
    
        const { account, credential, oAuth2Client, oAuth2Clientv3: drive } = await initialGoogleDrive(aid);
        const fileMetadata = {
            name: file.originalname,
            parents: [folderId], // Google Drive folder ID
        };

        const media = {
            body: fs.createReadStream(file.path),
        };

        const response = await drive.files.create({
            resource: fileMetadata,
            media,
            fields: 'id,name',
        });
        fs.unlinkSync(file.path); // Clean up local file
        return { success: true, fileId: response.data.id };
    } catch (error) {
        return { success: false, error: error.message };
    }

}   

const downloadGoogleDriveFile = async (req, res) => {
    const { fid, aid } = req.body;
    
    try {
        const { account, credential, oAuth2Client, oAuth2Clientv3: drive } = await initialGoogleDrive(aid);
        const { data: fileMetadata } = await drive.files.get({
            fileId: fid,
            fields: 'id, name, mimeType',
        });

        if (fileMetadata.mimeType === 'application/vnd.google-apps.folder') {
            // Handle folder download as ZIP
            await downloadFolderAsZip(drive, fid, fileMetadata.name, res);
        } else {
            // Try to download single file first
            try {
                await downloadSingleFile(drive, fid, fileMetadata, res);
            
            } catch (error) {
                console.error('Single file download failed, attempting ZIP download:', error.message);
                // Fallback to downloading as ZIP
                await downloadFileAsZip(drive, fileMetadata, res);
            }
        }
    } catch (error) {
        console.error('Failed to download file:', error.message);
        res.status(500).send({ error: `Error downloading file: ${error.message}` });
    }
};


/**
 * Helper function to download a single file
 */
const downloadSingleFile = async (drive, fileId, fileMetadata, res) => {
    const { name: fileName, mimeType } = fileMetadata;
    

    // Export if it's a Google Docs file, otherwise download directly
    if (mimeType.startsWith('application/vnd.google-apps')) {

        const exportMimeType = getCompatibleOfficeMimeType(mimeType);
        if (!exportMimeType) throw new Error('Unsupported Google Docs file type');
        // const { exportMimeType, fileExtension } = getExportMimeTypeAndExtension(mimeType);
        const exportResponse = await drive.files.export(
            { fileId, mimeType: exportMimeType },
            { responseType: 'stream' }
        );

        res.set({
            'Content-Disposition': `attachment; filename="${fileName}"`,
            'Content-Type': exportMimeType,
        });

        exportResponse.data.pipe(res);
    } else {
        const response = await drive.files.get(
            { fileId, alt: 'media' },
            { responseType: 'stream' }
        );

        res.set({
            'Content-Disposition': `attachment; filename="${fileName}"`,
            'Content-Type': 'application/octet-stream',
        });

        response.data.pipe(res);
    }
   
};

/**
 * Helper function to get a compatible Office MIME type based on Google Docs type
 */
const getCompatibleOfficeMimeType = (mimeType) => {
    switch (mimeType) {
        case 'application/vnd.google-apps.document':
            return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'; // .docx
        case 'application/vnd.google-apps.spreadsheet':
            return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'; // .xlsx
        case 'application/vnd.google-apps.presentation':
            return 'application/vnd.openxmlformats-officedocument.presentationml.presentation'; // .pptx
        default:
            return null; // Unsupported Google Docs type
    }
};


/**
 * Helper function to download a folder as a ZIP
 */
const downloadFolderAsZip = async (drive, folderId, folderName, res) => {
    const archive = archiver('zip', { zlib: { level: 9 } });

    res.set({
        'Content-Disposition': `attachment; filename="${folderName}.zip"`,
        'Content-Type': 'application/zip',
    });

    archive.pipe(res);

    try {
        // const response = await drive.files.list({
        //     q: `'${folderId}' in parents`,
        //     fields: 'files(id, name, mimeType)',
        // });

        // const files = response.data.files;

        // // Append each file to the archive
        // for (const file of files) {
        //     const stream = await getFileStream(drive, file);
        //     archive.append(stream, { name: file.name });
        // }

        await addFolderToArchive(drive, folderId, folderName, archive);
        // Finalize the archive
        archive.finalize();
    } catch (error) {
        throw new Error(`Failed to download folder as ZIP: ${error.message}`);
    }
};

/**
 * Recursive function to add folder contents (including subfolders) to the archive
 */
const addFolderToArchive = async (drive, folderId, folderName, archive) => {
    const response = await drive.files.list({
        q: `'${folderId}' in parents and trashed = false`,
        fields: 'files(id, name, mimeType)',
    });

    const files = response.data.files;

    for (const file of files) {
        const entryPath = `${folderName}/${file.name}`;
        
        if (file.mimeType === 'application/vnd.google-apps.folder') {
            // Recursively add subfolder
            await addFolderToArchive(drive, file.id, entryPath, archive);
        } else {
            // Add individual file to the archive
            const stream = await getFileStream(drive, file);
            archive.append(stream, { name: entryPath });
        }
    }
};


/**
 * Helper function to download a single file as ZIP if direct download fails
 */
const downloadFileAsZip = async (drive, fileMetadata, res) => {
    const archive = archiver('zip', { zlib: { level: 9 } });

    res.set({
        'Content-Disposition': `attachment; filename="${fileMetadata.name}.zip"`,
        'Content-Type': 'application/zip',
    });

    archive.pipe(res);

    const stream = await getFileStream(drive, fileMetadata);
    archive.append(stream, { name: fileMetadata.name });

    // Finalize the archive
    archive.finalize();
};

/**
 * Helper function to get a file stream, exporting if it's a Google Docs file
 */
const getFileStream = async (drive, file) => {
    if (file.mimeType.startsWith('application/vnd.google-apps')) {
        // const { exportMimeType } = getExportMimeTypeAndExtension(file.mimeType);
        const exportResponse = await drive.files.export(
            { fileId: file.id, mimeType: file.mimeType },
            { responseType: 'stream' }
        );
        return exportResponse.data;
    } else {
        const fileResponse = await drive.files.get(
            { fileId: file.id, alt: 'media' },
            { responseType: 'stream' }
        );
        return fileResponse.data;
    }
};
 

const deleteFileFromGoogleDrive = async (aid,fid)=>{
    try{
        // Find the account and credentials
        const {account,credential,oAuth2Clientv3} = await initialGoogleDrive(aid)
        
        // Delete the file
        await oAuth2Clientv3.files.delete({
            fileId: fid,
        });

        return createSuccessResponse({},'File deleted successfully.' )
        
    } catch (error) {
        console.error('Failed to delete file:', error.message);
        return createErrorResponse(`Failed to delete file. Error: ${error.message}`);
    }
}


// export const driveStatus = async(email:String)=>{
const googleDriveStatus = async(id)=>{
    let account = await Account.findById(id)
    if (!account) 
    return {
        succes:false,
        message:"Account not found",
        data:{}
    }
    try{
        
        
        
        let credential = await Credential.findById(account.credentialId )
        if(!credential) 
        return {
            success:false,
            message: "Credential not found",
            data:{}
        }
        
        let decryptedCredential = JSON.parse(decrypt(credential.credential))
        const { client_id, client_secret, redirect_uris } = decryptedCredential.installed || decryptedCredential.web;
        
        
        const oAuth2Client = new google.auth.OAuth2(
            client_id,
            client_secret,
            redirect_uris
        )
        

        let cre =JSON.parse(decrypt(account.tokens))
      
        // console.log(JSON.parse(decrypt(account.tokens)))
        oAuth2Client.setCredentials(cre)
    
        // Initialize the Google Drive API
        const drive = google.drive({ version: 'v3', auth: oAuth2Client });

        // Use the 'about.get' endpoint to retrieve user information including storage
        const  {data}  = await drive.about.get({
            fields: 'storageQuota' // Only get the storage info
        });
        // console.log("Storage Quota:",data)
        const usagePercentage = (Number(data.storageQuota?.usage) / Number(data.storageQuota?.limit)) * 100;

        const d ={
            totalStorage: formatBytes(Number(data.storageQuota?.limit)),  // Total storage in human-readable format
            usedStorage:  formatBytes(Number(data.storageQuota?.usage)),   // Used storage
            driveStorage: formatBytes(Number(data.storageQuota?.usageInDrive)), // Google Drive storage used
            trashStorage: formatBytes(Number(data.storageQuota?.usageInDriveTrash)) ,// Storage used by trash
            usagePercentage: usagePercentage.toFixed(2)
        }
        
        return {
            success:true,
            message:"get successful",
            data:d
        }
    } catch (error) {
        account.isAuthorized = false
        account.isActive = false
        await account.save()
        return {
            success:false,
            message: `An error occurred while fetching Google Drive usage. Error:${error.message}`, 
            data:{}
        }
        
    }
}

//Get all Google Drive Status (Dashboard)
    const fetchGoogleDriveStatus = async(uid)=>{
    try {
        const accounts = await Account.find({
            $or:[
                {isPublic:true},
                {uid:uid},
            ]
        }).populate({path:'credentialId',select:'provider'})
        if (!accounts) 
        return {
            success:false,
            message:"Accounts not found",
            data:{}
        }
        let data =  await Promise.all(accounts.map(async (account) => {
            if (!(account.credentialId instanceof mongoose.Types.ObjectId)) {
                let tokens = JSON.parse(decrypt(account.tokens));
                let access_token = `${(tokens.access_token).substring(0, 5)}...${(tokens.access_token).substring(150, 155)}...${(tokens.access_token).substring(tokens.access_token.length - 4)}`;
                // Call googleDriveStatus for this account and get drive usage
                let driveUsage;
                try {
                    driveUsage = await googleDriveStatus(account._id);
                } catch (error) {
                    driveUsage = {
                        success: false,
                        message: `Failed to fetch drive usage: ${error.message}`,
                        data: {}
                    };
                }
                return {
                    _id: account._id, // XXXEncrypted _id
                    email: account.email,
                    provider: account.credentialId.provider, // Accessing from Credential model
                    token: access_token,
                    isAuthorized: account.isAuthorized,
                    isActive: account.isActive,
                    isPublic: account.isPublic,
                    usage: driveUsage.data
                };
            } else {
                return {};
            }
        }))
        

        return { 
            success:true,
            message:'',
            data:data
        };
    
    } catch (error) {
        return { 
            success:false,
            message: `An error occurred while listing drive status. Error: ${error.message}`, 
            data:{}
        };
    }
}

    const fetchFilesByGoogleFolder = async(folderId,uid)=>{
    
    try{
        const account = await findAccountById(uid)
        if (!account.success) 
            return {
                succes:false,
                message:account.message,
                data:account.data
            }

        const q = await getCredentialById(account.data.credentialId)
        if(!q.success) 
        return {
            success:false,
            message:q.message,
            data:{}
        }
        let credential = JSON.parse(decrypt(q?.data?.credential))
        const oAuth2Client = new google.auth.OAuth2(
            credential.data.client_id,
            credential.data.client_secret,
            credential.data.redirect_uris
        )
        oAuth2Client.setCredentials(account.data.tokens)
        const drive = google.drive('v3');
            
        let response = await drive.files.list({
            auth: oAuth2Client,
            q:`'${folderId}' in parents`,
            fields: 'files(id, name, mimeType,size,createdTime,modifiedTime)',
        })
        return { 
            success:true,
            message:'',
            data:response.data.files
        };
    } catch (error) {
        return { 
            success:false,
            message: `An error occurred while listing files for account. Error: ${error.message}`, 
            data:{}
        };
    }
                
}
    

// const uploadFileToGoogleDrive = async (req, res) => {
//     const { accountId, folderId, cloudProvider } = req.body;

//     try {
//         // Get file data from the request
//         const filePath = req.file.path;
//         const fileName = req.file.originalname;

//         // Choose the appropriate function based on cloudProvider
//         if (cloudProvider === 'google') {
//             await uploadToGoogleDrive(accountId, folderId, filePath, fileName);
//         } else if (cloudProvider === 'dropbox') {
//             await uploadToDropbox(accountId, folderId, filePath, fileName);
//         }
        
//         res.status(200).json({ success: true, message: 'File uploaded successfully!' });
//     } catch (error) {
//         console.error('Upload error:', error);
//         res.status(500).json({ success: false, message: 'Failed to upload file.' });
//     }
// };










 const isTokenExpired = (expiresAt)=>{
    // if it is true then token is expired
    const now = new Date();
    return new Date(expiresAt) <= now;   //1726500227689  <= 1726499378759
}


const refreshGoogleToken = async (req,res) => {
    try {
        const {accountId} = req.body
        // Find the account
        const account = await Account.findById(accountId);
        if (!account) {
            return res.status(404).send({ status: false, message: "Account not found" });
        }

        if (account.provider !== "google") {
            return res.status(404).send({ status: false, message: "Invalid provider. This account is not a Google account." });
        }

        // Fetch associated credentials
        const credential = await Credential.findById(account.credentialId);
        if (!credential) {
            return res.status(404).send({ status: false, message: "Credential not found" });
        }

        //Decrypt token and client credentials
        const tokens = JSON.parse(decrypt(account.tokens))
        const decryptedCredential = JSON.parse(decrypt(credential.credential));
        const { client_id, client_secret } = decryptedCredential.web || decryptedCredential.installed;

        // Use the refresh_token to get a new access token
        if (!tokens.refresh_token) {
            return res.status(404).send({ status: false, message: "Refresh token not found in account tokens." });
        }

        const tokenEndpoint = "https://oauth2.googleapis.com/token";

        const response = await axios.post(tokenEndpoint, null, {
            params: {
                client_id,
                client_secret,
                refresh_token: tokens.refresh_token,
                grant_type: "refresh_token",
            },
        });

        const { access_token, expires_in, id_token, scope, token_type } = response.data;

        // Update the tokens in the database
        tokens.access_token = access_token;
        console.log('expiry_date ',expires_in)
        tokens.expiry_date = Date.now() + expires_in * 1000; // Convert expires_in to milliseconds
        if (id_token) {
            account.tokens.id_token = id_token;
        }
        tokens.scope = scope;
        tokens.token_type = token_type;
        account.tokens = encrypt(JSON.stringify(tokens))

        account.isAuthorized = account.isAuthorized===false? true:account.isAuthorized
        await account.save();

        return res.status(200).send({
            status: true,
            message: "Token refreshed successfully.",
            account: {
                id: account._id,
                email: account.email,
                tokens: tokens.access_token, // Only send the access token back
            },
        });
    } catch (error) {
        console.error("Error refreshing Google token:", error.response?.data || error.message);
        return res.status(500).send({
            status: false,
            message: "Failed to refresh token.",
            error: error.response?.data || error.message,
        });
    }
};

const refreshGoogleTokens = async (req, res) => {
    try {
        const { userId } = req.body; // List of account IDs from the frontend

        // // Fetch accounts based on accountIds or all Google accounts if accountIds is not provided
        // const query = accountIds?.length
        //     ? { _id: { $in: accountIds }, provider: "google" }
        //     : { provider: "google" };

        // const accounts = await Account.find(query);

        // if (!accounts.length) {
        //     return res.status(404).send({ status: false, message: "No Google accounts found." });
        // }
        const accounts = await Account.find({ uid: userId, provider: 'google', isActive: true });
        if (!accounts || accounts.length === 0) {
            return res.status(404).send({ status: false, message: "No active Google accounts found." });
        }
        const updatedAccounts = [];
        const errors = [];

        for (const account of accounts) {
            try {
                // Fetch associated credentials
                const credential = await Credential.findById(account.credentialId);
                if (!credential) throw new Error("Credential not found");

                // Decrypt the client credentials
                const decryptedCredential = JSON.parse(decrypt(credential.credential));
                const { client_id, client_secret } = decryptedCredential.web || decryptedCredential.installed;

                // Decrypt the account tokens
                const tokens = JSON.parse(decrypt(account.tokens));

                if (!tokens.refresh_token) throw new Error("Refresh token not found in account tokens");

                // Use the refresh_token to get a new access token
                const tokenEndpoint = "https://oauth2.googleapis.com/token";
                const response = await axios.post(tokenEndpoint, null, {
                    params: {
                        client_id,
                        client_secret,
                        refresh_token: tokens.refresh_token,
                        grant_type: "refresh_token",
                    },
                });

                const { access_token, expires_in, id_token, scope, token_type } = response.data;

                // Update the tokens
                tokens.access_token = access_token;
                tokens.expiry_date = Date.now() + expires_in * 1000; // Convert expires_in to milliseconds
                if (id_token) tokens.id_token = id_token;
                tokens.scope = scope;
                tokens.token_type = token_type;

                account.tokens = encrypt(JSON.stringify(tokens));
                account.isAuthorized = true; // Mark account as authorized
                await account.save();

                updatedAccounts.push({ accountId: account._id, tokens, email: account.email });
            } catch (err) {
                console.error(`Error refreshing token for account ${account._id}:`, err.message);
                errors.push({ accountId: account._id, email: account.email, error: err.message });
            }
        }

        return res.status(200).send({
            status: true,
            message: "Token refresh completed.",
            updatedAccounts,
            errors,
        });

    } catch (error) {
        console.error("Error in refreshGoogleTokens:", error.message);
        return res.status(500).send({
            status: false,
            message: "Failed to refresh tokens.",
            error: error.message,
        });
    }
};


 const refreshGoogleToken2 = async(req,res)=>{
    try{
        const {aid} = req.body
        const q = await Account.findById(aid)
        if(!q) return res.status(404).send({status:false,message:"Account not found"})
        console.log("here1")
        const c = await Credential.findById(q.credentialId)
        if(!c) return res.status(404).send({status:false,message:"Credential not found"})
            console.log("here2")

        const tokens = JSON.parse(decrypt(q.tokens)) 
        if(!tokens.refresh_token) return res.status(404).send({status:false,message:"Refresh token not found"})
        const credential = JSON.parse(decrypt(c.credential))
        console.log(credential)
        let {client_id,client_secret} = credential.installed || credential.web
        //  const { token } = await oAuth2Client.getAccessToken();
        console.log("here3")
        const response = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: client_id,
                client_secret: client_secret,
                refresh_token: tokens.refresh_token,
                grant_type: 'refresh_token',
            }),
        });
        console.log("here4")
        const data = await response.json();
        if (!data.access_token) {
            throw new Error('Failed to refresh token');
        }
        console.log("here5")
        tokens.access_token = data.access_token
        q.tokens = encrypt(JSON.stringify(tokens))
        await q.save()
        return res.status(200).send({
            accessToken: data.access_token,
            expiresIn: data.expires_in, // seconds
        });
       
        
    } catch (error) {
        console.log(error.message)
        return res.status(200).send({
            message:error.message
        })
    }
}

// Revoke Google Account access
const revokeGoogleAccountAccess = async (req, res) => {
    const { accountId } = req.body; // Account ID to revoke access for

    // Step 1: Find the account by accountId
    const account = await Account.findById(accountId);
    if (!account) {
        return res.status(404).send({ status: false, message: "Account not found" });
    }

    if (account.provider !== "google") {
        return res.status(400).send({ status: false, message: "This account is not a Google account." });
    }
    try {

        // Step 2: Fetch the credentials
        const credential = await Credential.findById(account.credentialId);
        if (!credential) {
            return res.status(404).send({ status: false, message: "Credential not found" });
        }

        // Step 3: Decrypt tokens
        const tokens = JSON.parse(decrypt(account.tokens)); 

        if (!tokens.access_token && !tokens.refresh_token) {
            return res.status(400).send({ status: false, message: "No access token or refresh token found" });
        }

        // Step 4: Revoke the access token via Google API
        const revokeUrl = `https://oauth2.googleapis.com/revoke?token=${tokens.access_token}`;

        await axios.post(revokeUrl);
        
        // revoke the refresh token if existed
        if (tokens.refresh_token) {
            const revokeRefreshUrl = `https://oauth2.googleapis.com/revoke?token=${tokens.refresh_token}`;
            await axios.post(revokeRefreshUrl);
        }

        // Step 5: Delete account
        await Account.findByIdAndDelete(account._id)


        return res.status(200).send({
            status: true,
            message: "Google account access revoked successfully.",
        });

    } catch (error) {
        // Step 5: Delete account
        console.error("Error revoking Google account access:", error.message);
        await Account.findByIdAndDelete(account._id)
        return res.status(500).send({
            status: false,
            message: "Failed to revoke Google account access.",
            error: error.message,
        });
    }
};

//  const revokeGoogleAccount = async(req,res)=>{
//     try{
//         const token = req.body.token
//         console.log("Token, ",token)
//         if (!token) 
//         return res.status(404).json({
//             success:false,
//             message:"token not found"
//         })
        
//         const account = await Account.findOne({_id:token})
//         if (!account) 
//         return res.status(404).json({
//             success:false,
//             message:"account not found"
//         })

//         // Decrypt the tokens
//         const decryptedToken = JSON.parse(decrypt(account.tokens))
//         const oAuth2Client = new google.auth.OAuth2();
//         oAuth2Client.setCredentials({
//             access_token: decryptedToken.access_token,
//             refresh_token: decryptedToken.refresh_token,
//         });

//         // Revoke the access token
//         await oAuth2Client.revokeToken(decryptedToken.refresh_token);
//         await Account.findByIdAndDelete(account._id)

//         return res.status(204).json({ 
//             success:true,
//             message: 'Account revoked successfully' 
//         });
//     } catch (error) {
//         console.log(error.message)
//         await Account.findByIdAndDelete(req.body.token)
//         return res.status(500).json({
//             success:false,
//             message: 'An error occurred during revocation', error: error.message 
//         });
//     }

// }
const revokeGoogleAccount = async(tokens)=>{
    try{
        const revokeUrl = `https://oauth2.googleapis.com/revoke?token=${tokens.access_token}`;
        await axios.post(revokeUrl);

        // revoke the refresh token if existed
        if (tokens.refresh_token) {
            const revokeRefreshUrl = `https://oauth2.googleapis.com/revoke?token=${tokens.refresh_token}`;
            await axios.post(revokeRefreshUrl);
        }
        
    } catch (error) {
        console.log(error.message)
    }
}


//internal Methods
 const revokeAccounts= async(credentialId ="")=>{
    try {
        let q
        if(credentialId)
            q = await Account.find({credentialId:credentialId})
        else
            q = await Account.find()

        if(!q){
            console.log('Accounts not found')
            return true
        } 
        await Promise.all(q.map(async(account)=>{
            // Decrypt the tokens
            const decryptedToken = JSON.parse(decrypt(account.tokens))
            const oAuth2Client = new google.auth.OAuth2();
            oAuth2Client.setCredentials({
                access_token: decryptedToken.access_token,
                refresh_token: decryptedToken.refresh_token,
            });

             // Revoke the access token
            await oAuth2Client.revokeToken(decryptedToken.refresh_token);
            await Account.findByIdAndDelete(account._id)
            console.log(`Account ${account.email} revoked`)
        }))
        

        // Delete all accounts with the specified credentialId
        let result = null
        if(credentialId)
        {
            result = await Account.deleteMany({ credentialId });
            console.log(`${result.deletedCount} accounts deleted with credentialId: ${credentialId}`);
        }
        else{
            result = await Account.deleteMany();
            console.log(`${result.deletedCount} accounts deleted`);
        }

        return true;
    } catch (error) {
        console.error(`Error deleting accounts with credentialId ${credentialId}: `, error);
        return false
    }
}





module.exports = {
    initiateGoogleAuth,
    reauthoriseGoogleAuth,
    oauth2Callback,
    
    fetchGooglefolder,
    fetchAllGoogleDriveFiles,
    uploadToGoogleDrive,
    downloadGoogleDriveFile,
    deleteFileFromGoogleDrive,
    isTokenExpired,
    revokeAccounts,
    googleDriveStatus,
    fetchGoogleDriveStatus,
    fetchFilesByGoogleFolder,
    listAllDriveWithFiles,


    //New
    setGoogleCredential,
    refreshGoogleToken,
    refreshGoogleTokens,
    revokeGoogleAccountAccess,

    generateAuthLink,
    oAuthCallBack,
    revokeGoogleAccount,

    
};
