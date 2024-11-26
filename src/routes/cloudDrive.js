// Import required functions
const express = require('express');
const multer = require('multer');
// const fs = require('fs');
const {
    fetchDropboxFiles,
    listAllDropboxWithFiles,
    revokeDropbox,
    uploadToDropbox,
    downloadDropboxFile,
    deleteDropboxFile,
    refreshDropboxToken,
    refreshMultipleDropboxTokens,
    revokeDropboxAccountAccess
} = require('../controllers/cloudAPIControllers/dropboxController');

const {
    setGoogleCredential,
    fetchGooglefolder,
    listAllDriveWithFiles,
    uploadToGoogleDrive,
    downloadGoogleDriveFile,
    deleteFileFromGoogleDrive,
    refreshGoogleToken,
    refreshGoogleTokens,
    revokeGoogleAccountAccess,
    revokeGoogleAccount,

} = require('../controllers/cloudAPIControllers/googleDriveController');
const Account = require('../models/Account');
const Credential = require('../models/credential');
const { decrypt } = require('../utils/encryption');


const router = express.Router();
const upload = multer({ dest: 'temp/' }).single('file');

// Combined route to fetch files from both Google Drive and Dropbox
router.post('/', async (req, res) => {
    const { uid } = req.body;

    try {
        // Fetch Google Drive files
        const googleDriveData = await listAllDriveWithFiles(uid);

        // Fetch Dropbox files
        const dropboxData = await listAllDropboxWithFiles(uid);

        // Check if both responses are successful
        if (!googleDriveData.success || !dropboxData.success) {
            return res.status(500).json({
                success: false,
                message: "Failed to retrieve files from one or both providers",
            });
        }

        // Combine Google Drive and Dropbox data
        const combinedData = [
            ...googleDriveData.data.map((driveData) => ({
                ...driveData,
                drive: { ...driveData.drive, provider: "google" }
            })),
            ...dropboxData.data.map((dropboxData) => ({
                ...dropboxData,
                drive: { ...dropboxData.drive, provider: "dropbox" }
            }))
        ];

        // Return combined data
        res.status(200).json({
            success: true,
            message: "Data retrieved successfully",
            data: combinedData
        });
    } catch (error) {
        console.error("Error fetching files:", error.message);
        res.status(500).json({
            success: false,
            message: `Error retrieving files: ${error.message}`
        });
    }
});




//Google Drive routes
router.post('/googledrive/files', async (req, res) => {
    const { fid = "root", aid } = req.body;
    const data = await fetchGooglefolder(fid, aid);
    res.status(200).json({
        success: data?.success,
        message: data.message,
        data: data.data
    });
});

//Upload File
router.post('/upload/google',upload, async (req, res) => {
    try {
        
        const { aid, folderId } = req.body;
        const file = req.file
        
        const uploadResponses = await uploadToGoogleDrive(aid,folderId,file)

        res.status(200).json(uploadResponses);
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ success: false, message: 'Upload failed.' });
    }
})

//download file
router.post('/googledrive/download', downloadGoogleDriveFile);

//delete drive file
router.delete('/googledrive/delete', async (req, res) => {
    const { aid, filePath } = req.body;
    const data = await deleteFileFromGoogleDrive(aid, filePath);
    res.status(200).json({
        success: data?.success,
        message: data.message,
        data: data.data
    });
});

//refresh token
router.post('/googledrive/refresh-token', refreshGoogleToken);
router.post('/googledrive/refresh-tokens', refreshGoogleTokens);
router.post('/dropbox/refresh-token', refreshDropboxToken);
router.post('/dropbox/refresh-tokens', refreshMultipleDropboxTokens);

//Revoke an account
router.delete('/googledrive/revoke', revokeGoogleAccountAccess);

//Set credential
router.post('/googledrive/upload', setGoogleCredential);





//Dropbox routes
//Fetch files in folder (default is root)
router.post('/dropbox/files', async(req,res)=>{

    const {aid,fid=""} = req.body
    const account =  await Account.findById(aid)
    if(!account) return res.status(404).json({status:false, message:"Account not found"})
    const response =await fetchDropboxFiles(fid,aid)
    res.status(200).json(response);
});

//get list of dropbox files
router.post('/dropbox', async(req,res)=>{
    //A method used to fetch account and its files
    //listDropbox
    const {uid} = req.body
    const response =await listAllDropboxWithFiles(uid)
    res.status(200).json(response);
})

//Upload File
router.post('/upload/dropbox',upload, async (req, res) => {
    try {
        
        const { aid, path:folderPath } = req.body;
        const file = req.file
        if (!file || !folderPath) {
            return res.status(400).send({ success: false, message: 'File or path missing' });
        }
        const uploadResponses = await uploadToDropbox(aid,decodeURIComponent(folderPath),file)
        
        res.status(200).json(uploadResponses);
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ success: false, message: `Upload failed. ${error.message}` });
    }
})

//Revoke an account
router.delete('/dropbox/revoke', revokeDropboxAccountAccess);

//download file
router.post('/dropbox/download', downloadDropboxFile);
router.delete('/dropbox/delete', deleteDropboxFile)

router.post('/reset', async (req, res) => {
    const { email, uid } = req.body;
    const credential = await Credential.findOne({ provider: "config", type: "config" })
    const decryptedCredential = JSON.parse(decrypt(credential.credential))
    if (!credential || uid !== decryptedCredential.admin) {
        return res.status(403).send({
            success: false,
            message: "Unauthorized: Invalid admin credentials.",
        });
    }

    const accounts = await Account.find()
    if(!accounts) return res.status(404).send({
        success: false,
        message: "No accounts found",
    });
    try {
        // Revoke and delete accounts
        const accountIdsToDelete = [];
        for (const account of accounts) {
            try {
                const tokens = JSON.parse(decrypt(account.tokens));
                if (account.provider === "google") {
                    await revokeGoogleAccount(tokens);
                } else if (account.provider === "dropbox") {
                    await revokeDropbox(tokens);
                }
                accountIdsToDelete.push(account._id);
            } catch (err) {
                console.error(`Error revoking account ${account._id}:`, err.message);
                continue; // Skip this account and move on to the next
            }
        }
        // Batch delete accounts
        await Account.deleteMany({ _id: { $in: accountIdsToDelete } });

        // Delete related credentials
        await Credential.deleteMany();

        return res.send({
            success: true,
            message: "Project data reset successfully for the user.",
        });
        
    } catch (error) {
        console.error("Error during project data reset:", error);
        res.status(500).send({
            success: false,
            message: "Failed to reset project data.",
            error: error.message,
        });
    }
})



//Export
module.exports = router;