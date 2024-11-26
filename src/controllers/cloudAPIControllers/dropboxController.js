const DropboxAuth = require('dropbox').DropboxAuth;
const url = require('url');
const fs = require('fs');
const { Dropbox } = require('dropbox');
const axios = require('axios')


const Account = require('../../models/Account');
const Credential = require('../../models/Credential');
const  {findCredentialByCloudAPI}  = require(  '../credentialsController');

const { formatBytes } = require( '../../utils/bytesConverter');
const { createSuccessResponse,createErrorResponse} = require('../../utils/setupResponse')
const { decrypt, encrypt } = require('../../utils/encryption');

const REDIRECT_URI = 'http://localhost:3000/api/auth/dropbox/callback';

// Utility function to create Dropbox Auth client
const createDropboxAuthClient = (config) => {
    if (!config.clientId || !config.clientSecret) {
        throw new Error('Invalid credential data for Dropbox');
    }

    return new DropboxAuth({
        fetch:require('node-fetch'),
        clientId:config.clientId,
        clientSecret:config.clientSecret
    });
};

// Function to generate an authentication URL
const generateDropboxAuthUrl = async (dbxAuthClient, redirectUri, state) => {
    return await dbxAuthClient.getAuthenticationUrl(
        redirectUri,
        encodeURIComponent(JSON.stringify(state)),
        'code',
        'offline',
        [],
        'none',
        false
    );
};

//Configuration
const initialDropbox = async(aid) =>{
    try {
        
        let account = await Account.findById(aid) || null
        if(!account) return {status:false,message:"Account not found"}
        account.tokens = decrypt(account.tokens)


        
        let c = await Credential.findById(account.credentialId) || null
        if(!c) return {status:false,message:"Credential not found"}
        c.credential = decrypt(c.credential)
        c = JSON.stringify(c)
        const credential = JSON.parse(c)
        credential.credential = JSON.parse(credential.credential)
        
        const dbxAuth = new DropboxAuth({
            fetch:require('node-fetch'),
            clientId:credential.clientId,
            clientSecret:credential.clientSecret
        })

        return {status:true,account,credential, dbxAuth}
    } catch (error) {
        console.log("Error: ",error.message)
        return {status:false,message:error.message}
    }
}

//Old
const initiateDropBoxAuth = async (req,res) => {
    try {
        const userId    = req.body.userId || req.query.userId;
        const credential = await findCredentialByCloudAPI('dropbox')
        if(!credential) return res.status(500).json({ message: 'Invalid credential data' }); 
        
        
        const dbx = createDropboxAuthClient(credential);
        const authUrl = await generateDropboxAuthUrl(dbx,REDIRECT_URI, { userId });

    
        if (!authUrl) {
            return res.status(500).json({ success: false, message: 'Failed to generate auth URL' });
        }

        res.status(200).json({
            success: true,
            message: 'Auth URL generated successfully',
            authUrl
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message:`Error initiating Dropbox Auth: ${error.message}` 
        });
    }
};

//Old
// Function to reauthorize Google Authentication
const reauthoriseDropboxAuth = async (req, res) => {
    try {
        const { token } = req.body;
        const account = await Account.findOne({ _id: token });
        if (!account) return res.status(404).json({success: false,message: 'Account not found'});
        

        const credential = await findCredentialByCloudAPI('dropbox');
        if (!credential) return res.status(404).json({success: false, message: 'Credential not found'});
       
        const dbx = createDropboxAuthClient(credential);
        const authUrl = await generateDropboxAuthUrl(dbx,REDIRECT_URI, { token:account._id });

        return res.status(200).json({success: true,message: "Get auth URL successful",authUrl});
    } catch (error) {
        return res.status(500).json({success: false,message: `An error occurred during re-authorise account. Error: ${error.message}`});
    }
};
//Old
const dropboxCallback = async (req,res) => {
    const { code, state: encodedState } = url.parse(req.url, true).query;
    const credential = await findCredentialByCloudAPI('dropbox')
        if(!credential)
            return res.status(500).json({ message: 'Invalid credential data' }); 
        
        
    const dbxClient = createDropboxAuthClient(credential);
    
    try {
        // console.log(req.query.redirectUri)
        const tokenResponse = await dbxClient.getAccessTokenFromCode(REDIRECT_URI, code);
        const tokens = tokenResponse.result;

        
        // Parse the state parameter to get the userId
        const state = JSON.parse(decodeURIComponent(encodedState));
        // Fetch user account info to get the email
        const dbx = new Dropbox({ accessToken: tokens.access_token })
        const accountInfo = await dbx.usersGetCurrentAccount();
        console.log(tokens)
        const userEmail = accountInfo.result.email;
        console.log(userEmail)
        
        if (!state.token) {
            const credential = await Credential.findOne({provider:'dropbox',type:'cloudAPI'})
            const account = await Account.findOne({ credentialId: credential._id, userId: state.userId });
            if (account) {
                return res.redirect(`http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent("Account already exists")}`);
            }
            // Save the tokens securely
            await Account.create({
                credentialId: credential._id,
                uid:state.userId,
                provider:"dropbox",
                tokens: encrypt(JSON.stringify(tokens)),
                email:userEmail + ' (Dropbox)',
                isActive: true,
                isPublic: true,
                isAuthorized: true
            });
        } else {
            const account = await Account.findOne({ _id: state.token });
            if (!account) {
                return res.status(404).json({ success: false, message: 'Account not found' });
            }

            account.tokens = encrypt(JSON.stringify(tokens));
            await account.save();
        }

       
      
        res.redirect('http://localhost:5173/oauth-success?status=success');
    } catch (error) {
        console.error('Error in Dropbox callback:', error.message);
        res.redirect(`http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(error.message)}`);
    }
};

const generateDropboxAuthLink = async(uid)=>{
    
    // Fetch associated credentials
    const credential = await Credential.findOne({provider:"dropbox",type:"cloudAPI"});
    if (!credential) {
        return res.status(404).send({ status: false, message: "Credential not found" });
    }

    //Decrypt client credentials
    const {clientId:client_id,clientSecret:client_secret} = JSON.parse(decrypt(credential.credential));
    let state = JSON.stringify({provider:"dropbox",uid})
    // const authUrl = `https://www.dropbox.com/oauth2/authorize?client_id=${client_id}&redirect_uri=${REDIRECT_URI}&response_type=code&force_reapprove=true&state=${state}`;
    const authUrl = new URL("https://www.dropbox.com/oauth2/authorize");
    authUrl.searchParams.append("client_id", client_id);
    authUrl.searchParams.append("redirect_uri", REDIRECT_URI);
    authUrl.searchParams.append("response_type", "code");
    authUrl.searchParams.append("token_access_type", "offline"); // Critical for refresh_token
    authUrl.searchParams.append("force_reapprove", true); 
    authUrl.searchParams.append("state", state); 
    
    return {authUrl}
}

const oAuthDropboxCallback = async (req, res) => {
    const { code, state: encodedState, error } = url.parse(req.url, true).query;

    if (error) {
        console.error("OAuth error:", error);
        return res.redirect(
            `http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(error)}`
        );
    }

    try {
        const { uid, provider } = JSON.parse(decodeURIComponent(encodedState));

        // Fetch associated credentials
        const credential = await Credential.findOne({ provider: "dropbox", type: "cloudAPI" });
        if (!credential) throw new Error("Credential not found");

        // Decrypt client credentials
        const decryptedCredential = JSON.parse(decrypt(credential.credential));
        const { clientId:client_id, clientSecret:client_secret } = decryptedCredential;

        // Exchange code for tokens
        const tokenResponse = await axios.post(
            "https://api.dropboxapi.com/oauth2/token",
            new URLSearchParams({
                code,
                grant_type: "authorization_code",
                client_id,
                client_secret,
                redirect_uri:REDIRECT_URI,
            }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        if (!tokenResponse.data.refresh_token) {
            console.error("No refresh_token received. Prompting user to reauthorize...");
            return res.redirect(
                `http://localhost:5173/reconnect?status=failure&message=${encodeURIComponent(
                    "Please reauthorize to ensure proper connection."
                )}`
            );
        }

        console.log("Token Response:", tokenResponse.data);

        const accessToken = tokenResponse.data.access_token;
        if (!accessToken) throw new Error("Access token not found in response");

        // Fetch user info
        const userInfoResponse = await axios.post(
            "https://api.dropboxapi.com/2/users/get_current_account",
            null,
            {
                headers: { 
                    Authorization: `Bearer ${accessToken}`, 
                    "Content-Type": "application/json", // Explicit Content-Type
                },
            }
        );

        console.log("User Info Response:", userInfoResponse.data);

        const { email } = userInfoResponse.data;

        // Check if the account already exists
        const existingAccount = await Account.findOne({ uid, email, provider });
        if (existingAccount) {
            return res.redirect(
                `http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(
                    "Account already connected"
                )}`
            );
        }

        // Save the account to the database
        await Account.create({
            credentialId: credential._id,
            uid,
            provider,
            tokens: encrypt(JSON.stringify(tokenResponse.data)),
            email,
            isActive: true,
            isPublic: true,
            isAuthorized: true,
        });

        res.redirect("http://localhost:5173/oauth-success?status=success");
    } catch (err) {
        console.error("Error during OAuth callback:", err.response?.data || err.message);
        res.redirect(
            `http://localhost:5173/oauth-success?status=failure&message=${encodeURIComponent(err.message)}`
        );
    }
};

// Revoke Dropbox Account Access
const revokeDropboxAccountAccess = async (req, res) => {
    try {
        const { accountId } = req.body; // Account ID to revoke access for

        // Step 1: Find the account by accountId
        const account = await Account.findById(accountId);
        if (!account) {
            return res.status(404).send({ status: false, message: "Account not found" });
        }

        if (account.provider !== "dropbox") {
            return res.status(400).send({ status: false, message: "This account is not a Dropbox account." });
        }

        // Step 2: Decrypt tokens
        const tokens = JSON.parse(decrypt(account.tokens)); 

        if (!tokens.access_token) {
            return res.status(400).send({ status: false, message: "No access token found." });
        }

        // Step 3: Revoke the access token via Dropbox API
        const revokeUrl = `https://api.dropboxapi.com/2/auth/token/revoke`; 

        try {
            await axios.post(revokeUrl, null, {
                headers: {
                    Authorization: `Bearer ${tokens.access_token}`,
                     "Content-Type": "application/json"
                },
            });
            console.log("Dropbox account revoked")
        } catch (apiError) {
            console.error("Dropbox API error:", apiError.response?.data || apiError.message);
            return res.status(apiError.response?.status || 500).send({
                status: false,
                message: "Failed to revoke Dropbox access.",
                error: apiError.response?.data || apiError.message,
            });
        }

        // Step 4: Update the account status
        await Account.findByIdAndDelete(account._id)



        return res.status(200).send({
            status: true,
            message: "Dropbox account access revoked successfully.",
        });
    } catch (error) {
        console.error("Error revoking Dropbox account access:", error.message);
        return res.status(500).send({
            status: false,
            message: "Failed to revoke Dropbox account access.",
            error: error.message,
        });
    }
};


//Revoke
const revokeDropbox = async (tokens) => {
    const revokeUrl = `https://api.dropboxapi.com/2/auth/token/revoke`; 
    try {
        await axios.post(revokeUrl, null, {
            headers: {
                Authorization: `Bearer ${tokens.access_token}`,
                    "Content-Type": "application/json"
            },
        });
        console.log("Dropbox account revoked")
    } catch (apiError) {
        console.error("Dropbox API error:", apiError.response?.data || apiError.message);
        return res.status(apiError.response?.status || 500).send({
            status: false,
            message: "Failed to revoke Dropbox access.",
            error: apiError.response?.data || apiError.message,
        });
    }

    console.log("Access revoked successfully for Dropbox account.");
    return { success: true, message: "Dropbox access revoked successfully" }

}


//List all drive and files data on dashboard  (/)
const listAllDropboxWithFiles = async (uid) => {
    try{
       
        const accounts =  await Account.find({
            $or: [
                { isPublic: true, isActive: true, isAuthorized: true,provider:"dropbox" },
                { uid:uid, isActive: true, isAuthorized: true,provider:"dropbox" }
            ]
        });
        if (!accounts) return { success: false, message: `Accounts not found` }

        const data = await Promise.all(accounts.map(async (account) => {
            const usageResult = await getDropboxStorageUsage(account)
            const fileResult = await fetchDropboxFiles("",account)

            const drive = {
                id: account._id,
                email: account.email,
                provider: account.provider,
                isAuthorized: account.isAuthorized,
                isActive: account.isActive,
                isPublic: account.isPublic,
                usage: usageResult
            };

            return {
                drive,
                files:fileResult.data || []
            }
        }))

        return createSuccessResponse(data,'')
    }catch(error){
        console.error("Error Dropbox access:", error.message);
        return { success: false, message: `Failed to retrive accounts: ${error.message}` }
    }
}

//Dropbox status (info)
const getDropboxStorageUsage = async (account) => {
    // const {account} = await initialDropbox(aid)
    // Initialize Dropbox with the access token
    // let tokens = JSON.parse(account.tokens)
    let tokens = JSON.parse(decrypt(account.tokens))
    const dbx = new Dropbox({ accessToken :tokens.access_token });

    try {
        const response = await dbx.usersGetSpaceUsage();
        // Calculate the storage usage details
        const totalStorage = response.result.allocation.allocated;
        const usedStorage = response.result.used;
        const data =  {
            totalStorage:  formatBytes(Number(totalStorage)),
            usedStorage: formatBytes(Number(usedStorage)),
            driveStorage: formatBytes(Number(usedStorage)),  // Dropbox does not separate trash and drive storage
            trashStorage: 'N/A',          // Dropbox API does not provide trash storage size
            usagePercentage:(((Number(usedStorage) / Number(totalStorage))) * 100).toFixed(2)
        };
        
        // Format the data to match the desired output
        return data
    } catch (error) {
        console.error('Error fetching Dropbox storage usage:', error.message);
        return {};
    }
};

// Fetch files from a specified folder
const fetchDropboxFiles = async (path = '',account) => {
    try{
        // const {status,account,credential,dbxAuth} = await initialDropbox(aid)
        
        // let tokens = JSON.parse(account.tokens)
        let tokens = JSON.parse(decrypt(account.tokens))
        
        const dbx = new Dropbox({accessToken:tokens.access_token});
        // Call the filesListFolder API to list files in the specified path
        let fileData = []
        let message = ""
        try {
            const response = await dbx.filesListFolder({ path });
             fileData = response.result.entries.map(file =>({
                id:file.id,
                name: file.name,
                type: file['.tag'],
                path: file.path_lower,
                size: file.size || 0,
                createdTime: file.client_modified || "-",
                modifiedTime: file.server_modified|| "-",
                source:"dropbox"
                // ...(file['.tag'] === 'file' && {
                //     createdTime: file.client_modified,
                //     modifiedTime: file.server_modified
                // })
            }))
            
            // return fileData;
        } catch (error) {
            if (error.error && error.error['.tag'] === 'expired_access_token') {
                console.log('Access token expired. Attempting to refresh...');
                
                // Refresh the token and retry the API call
                const newTokens = await dropboxRefreshToken(tokens,dbxAuth);
                dbx.setAccessToken(newTokens.access_token);
                account.tokens = encrypt(JSON.stringify(newTokens))
                await account.save()
                const response = await dbx.filesListFolder({ path });
                console.log('Files after refresh:');
                fileData = response.result.entries.map(file =>({
                    id:file.id,
                    name: file.name,
                    type: file['.tag'],
                    path: file.path_lower,
                    size: file.size || 0,
                    createdTime: file.client_modified || "-",
                    modifiedTime: file.server_modified|| "-",
                    source:"dropbox"
                    // ...(file['.tag'] === 'file' && {
                    //     createdTime: file.client_modified,
                    //     modifiedTime: file.server_modified
                    // })
                }))
               
            }
            message = error.message
            console.log(`Fetch Dropbox file error. ${error.message}`); // Throw if it's a different error
        } finally {
            
            return {
                success: true,
                message: message,
                data: fileData || []
            };
        }
    }catch(error){
        console.log(error.message)
        
    }

};

//Upload file
const uploadToDropbox = async(aid,folderPath,file)=>{
    const {account} = await initialDropbox(aid)
    

    try {
        //decrypt tokens
        let tokens = JSON.parse(account.tokens)
        
        // Configure Dropbox API
        const dropbox = new Dropbox({accessToken:tokens.access_token});
        const fileContent = fs.readFileSync(file.path);

        const response = await dropbox.filesUpload({
            path: `${folderPath}/${file.originalname}`,
            contents: fileContent,
        });
        
        // Clean up the temporary file
        fs.unlinkSync(file.path);
        return { success: true, message: 'File uploaded to Dropbox', response };
    } catch (error) {
        console.error(error);
        return { success: false, message: `Failed to upload to Dropbox. ${error.message}` };
    }
}

//Refresh Token
const refreshToken = async(tokens,client_id,client_secret)=>{
     // Make a request to Dropbox's token endpoint
     const tokenEndpoint = "https://api.dropbox.com/oauth2/token";
     const response = await axios.post(tokenEndpoint, null, {
         params: {
             client_id:client_id,
             client_secret:client_secret,
             refresh_token: tokens.refresh_token,
             grant_type: "refresh_token",
         },
         headers: {
             "Content-Type": "application/x-www-form-urlencoded",
         },
     });
    
     return response.data
}


const refreshDropboxToken = async (req, res) => {
    const { accountId } = req.body;
    // Fetch the account from the database
    const account = await Account.findById(accountId);
    if (!account) {
        return res.status(404).send({ status: false, message: "Account not found" });
    }

    if (account.provider !== "dropbox") {
        return res.status(400).send({ status: false, message: "Invalid provider. This is not a Dropbox account." });
    }

    // Fetch associated credentials
    const credential = await Credential.findById(account.credentialId);
    if (!credential) {
        return res.status(404).send({ status: false, message: "Credential not found" });
    }
    try {


        // Decrypt tokens and client credentials
        const tokens = JSON.parse(decrypt(account.tokens));
        const decryptedCredential = JSON.parse(decrypt(credential.credential));
        const { clientId, clientSecret } = decryptedCredential;

        if (!tokens.refresh_token) {
            return res.status(400).send({ status: false, message: "Refresh token not found in account tokens." });
        }

        // Make a request to Dropbox's token endpoint
        // const tokenEndpoint = "https://api.dropbox.com/oauth2/token";
        // const response = await axios.post(tokenEndpoint, null, {
        //     params: {
        //         client_id:clientId,
        //         client_secret:clientSecret,
        //         refresh_token: tokens.refresh_token,
        //         grant_type: "refresh_token",
        //     },
        //     headers: {
        //         "Content-Type": "application/x-www-form-urlencoded",
        //     },
        // });

        // const { access_token, expires_in, scope, token_type, refresh_token } = response.data;
        
        const { 
            access_token,
            expires_in, 
            scope, 
            token_type, 
            refresh_token 
        } = await refreshToken(tokens,clientId,clientSecret);

        // Update tokens in the database

        tokens.access_token = access_token;
        tokens.expires_in = expires_in
        tokens.expiry_date = Date.now() + expires_in * 1000; // Convert expiry time to milliseconds
        tokens.scope = scope;
        tokens.token_type = token_type;
        
        if (refresh_token) tokens.refresh_token = refresh_token; // Update if Dropbox issues a new refresh token
        account.tokens = encrypt(JSON.stringify(tokens));
        account.updatedAt = Date.now()
        account.isAuthorized = true; // Ensure the account is marked as authorized
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
        console.error("Error refreshing Dropbox token:", error.response?.data || error.message);
        account.isAuthorized = false; // Ensure the account is marked as authorized
        await account.save();
        return res.status(500).send({
            status: false,
            message: "Failed to refresh token.",
            error: error.response?.data || error.message,
        });
    }
};

const refreshMultipleDropboxTokens = async (req, res) => {
    try {
        const { userId } = req.body;

        // Fetch all active Dropbox accounts for the given user
        const accounts = await Account.find({ uid: userId, provider: 'dropbox', isActive: true });
        if (!accounts || accounts.length === 0) {
            return res.status(404).send({ status: false, message: "No active Dropbox accounts found." });
        }

        const updatedAccounts = [];
        const errors = [];

        for (let account of accounts) {
            try {
                // Fetch associated credentials
                const credential = await Credential.findById(account.credentialId);
                if (!credential) throw new Error("Credential not found");

                // Decrypt the account tokens and client credentials
                const tokens = JSON.parse(decrypt(account.tokens));
                const decryptedCredential = JSON.parse(decrypt(credential.credential));
                const { clientId, clientSecret } = decryptedCredential;

                if (!tokens.refresh_token) throw new Error("Refresh token not found");

                // Make the request to Dropbox's token endpoint
                const tokenEndpoint = "https://api.dropbox.com/oauth2/token";
                const response = await axios.post(tokenEndpoint, null, {
                    params: {
                        client_id:clientId,
                        client_secret:clientSecret,
                        refresh_token: tokens.refresh_token,
                        grant_type: "refresh_token",
                    },
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                });

                const { access_token, expires_in, scope, token_type, refresh_token } = response.data;

                // Update tokens in the database
                tokens.access_token = access_token;
                tokens.expiry_date = Date.now() + expires_in * 1000; // Convert expiry time to milliseconds
                tokens.scope = scope;
                tokens.token_type = token_type;
                if (refresh_token) tokens.refresh_token = refresh_token; // Update if Dropbox issues a new refresh token

                account.tokens = encrypt(JSON.stringify(tokens));
                account.isAuthorized = true; // Mark account as authorized
                await account.save();

                updatedAccounts.push({
                    id: account._id,
                    email: account.email,
                    tokens: tokens.access_token, // Only send back the access token
                });
            } catch (err) {
                console.error(`Error refreshing token for Dropbox account ${account._id}:`, err.message);
                errors.push({ accountId: account._id, email: account.email, error: err.message });
            }
        }

        return res.status(200).send({
            status: true,
            message: `${updatedAccounts.length} Dropbox account(s) token refreshed successfully.`,
            updatedAccounts,
            errors,
        });
    } catch (error) {
        console.error("Error refreshing Dropbox tokens:", error.message);
        return res.status(500).send({
            status: false,
            message: "Failed to refresh Dropbox tokens.",
            error: error.message,
        });
    }
};



/**
 * Main function to handle Dropbox file download
 */
const downloadDropboxFile = async(req,res)=>{
    const { fid:path, aid } = req.body; 
    

    try {
        // const account = await Account.findById(aid);
        // if (!account) {
        //     return res.status(404).send({ status: false, message: "Account not found" });
        // }
        const {account} = await initialDropbox(aid)
        let tokens = JSON.parse(account.tokens)
        const dropboxClient = new Dropbox({ accessToken:tokens.access_token,fetch:require('node-fetch') });
        const metadata = await dropboxClient.filesGetMetadata({ path });
        console.log("path",path)
        console.log("metadata",metadata.result)
        if (metadata.result['.tag'] === 'folder') {
            // If it's a folder, zip the contents
            await downloadFolderAsZip(dropboxClient, path, metadata.result.name, res);
        } else {
            // If it's a single file, download directly
            await downloadSingleFile(dropboxClient, path, metadata.result.name, res);
        }
    } catch (error) {
        console.error('Failed to download file:', error);
        res.status(500).send({ error: `Error downloading file: ${error.message}` });
    }
}


/**
 * Function to download a single file from Dropbox
 */
const downloadSingleFile = async (dropboxClient, path, fileName, res) => {
    const response = await dropboxClient.filesDownload({ path });

    res.set({
        'Content-Disposition': `attachment; filename="${fileName}"`,
        'Content-Type': 'application/octet-stream',
    });

    res.send(response.result.fileBinary);
};


/**
 * Function to download a Dropbox folder as a ZIP
 */
const archiver = require('archiver');
const downloadFolderAsZip = async (dropboxClient, folderPath, folderName, res) => {
    const archive = archiver('zip', { zlib: { level: 9 } });

    res.set({
        'Content-Disposition': `attachment; filename="${folderName}.zip"`,
        'Content-Type': 'application/zip',
    });

    archive.pipe(res);

    try {
        // // Get the folder's contents
        // const { entries } = await dropboxClient.filesListFolder({ path: folderPath });

        // // Process each file in the folder
        // for (const entry of entries) {
        //     if (entry['.tag'] === 'file') {
        //         const fileStream = await getFileStream(dropboxClient, entry.path_lower);
        //         archive.append(fileStream, { name: entry.name });
        //     }
        //     // For simplicity, skipping nested folders in this example.
        // }
        await addFolderToArchive(dropboxClient, folderPath, folderName, archive);

        // Finalize the archive
        archive.finalize();
    } catch (error) {
        throw new Error(`Failed to download folder as ZIP: ${error.message}`);
    }
};

/**
 * Recursive function to add folder contents (including subfolders) to the archive
 */
const addFolderToArchive = async (dropboxClient, folderPath, folderName, archive) => {
    const response = await dropboxClient.filesListFolder({ path: folderPath });
    let entries = response.result.entries
    // for (const entry of entries) {
    //     const entryPath = `${folderName}/${entry.name}`;
        
    //     if (entry['.tag'] === 'file') {
    //         // Add file to the archive
    //         const fileStream = await getFileStream(dropboxClient, entry.path_lower);
    //         archive.append(fileStream, { name: entryPath });
    //     } else if (entry['.tag'] === 'folder') {
    //         // Recursively add subfolder to the archive
    //         await addFolderToArchive(dropboxClient, entry.path_lower, entryPath, archive);
    //     }
    // }
     for (const entry of entries) {
        
        const entryPath = `${folderName}/${entry.name}`;
        if(entry['.tag']==='file'){
            const fileStream = await getFileStream(dropboxClient, entry.path_lower);
            archive.append(fileStream, { name: entryPath });
        } else if (entry['.tag'] === 'folder') {
            // Recursively add subfolder to the archive
            await addFolderToArchive(dropboxClient, entry.path_lower, entryPath, archive);
        }
    }
};


/**
 * Helper function to download a file stream from Dropbox
 */
const getFileStream = async (dropboxClient, path) => {
    const response = await dropboxClient.filesDownload({ path });
    return Buffer.from(response.result.fileBinary);
};


const deleteDropboxFile = async (req, res) => {
    const { filePath, aid } = req.body;
    const {account} = await initialDropbox(aid)
    const tokens = JSON.parse(account.tokens)
    try {
        const dbx = new Dropbox({ accessToken:tokens.access_token });
        await dbx.filesDeleteV2({ path: filePath });
        res.status(200).json({ success: true, message: 'File deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to delete file', error: error.message });
    }
};


module.exports = {
    initiateDropBoxAuth,
    reauthoriseDropboxAuth,
    dropboxCallback,
    fetchDropboxFiles,
    listAllDropboxWithFiles,
    revokeDropbox,
    uploadToDropbox,
    downloadDropboxFile,
    deleteDropboxFile,


    //New Refresh Token
    refreshDropboxToken,
    refreshMultipleDropboxTokens,
    revokeDropboxAccountAccess,
    generateDropboxAuthLink,
    oAuthDropboxCallback,
    
};
