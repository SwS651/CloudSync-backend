const express = require('express');
const {
    downloadGooglDriveFile,
    deleteFileFromGoogleDrive,
    fetchAllGoogleDriveFiles,
    fetchFilesByGoogleFolder,
    fetchGooglefolder,
    fetchGoogleDriveStatus,
    googleDriveStatus,
    initiateGoogleAuth,
    listAllDriveWithFiles,
    oauth2Callback,
    reauthoriseGoogleAuth,
    revokeGoogleAccount,

    generateAuthLink,
    oAuthCallBack,
} = require('../controllers/cloudAPIControllers/googleDriveController');

const {encrypt, decrypt} = require('../utils/encryption');
const {
    dropboxCallback,
    initiateDropBoxAuth,
    reauthoriseDropboxAuth,
    generateDropboxAuthLink,
    oAuthDropboxCallback,


} = require('../controllers/cloudAPIControllers/dropboxController');
const setupFirebaseAdmin = require("../utils/firebaseAdmin");
const router = express.Router();


router.get("/users", async (req, res) => {
    try {
        // Ensure Firebase Admin SDK is set up
        const admin = await setupFirebaseAdmin();

        // Fetch all users (Example: list first 10 users from Firebase Auth)
        const listUsersResult = await admin.auth().listUsers(10);
        const users = listUsersResult.users.map(user => ({
            uid: user.uid,
            email: user.email,
            displayName: user.displayName,
            phoneNumber: user.phoneNumber,
            disabled: user.disabled,
        }));
        res.status(200).json({ status: true, users });
    } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({ status: false, message: "Failed to fetch users", error });
    }
});

// Get user profile
router.get("/profile", async (req, res) => {
    const userId = req.user?.uid; // Get userId from the authenticated user (e.g., from middleware)
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    try {
        const admin = await setupFirebaseAdmin();
        const user = await admin.auth().getUser(userId);

        const profile = {
            displayName: user.displayName,
            email: user.email,
            phoneNumber: user.phoneNumber,
        };

        res.status(200).json({ profile });
    } catch (error) {
        console.error("Error fetching user profile:", error);
        res.status(500).json({ message: "Failed to fetch profile", error });
    }
});

router.put("/profile", async (req, res) => {
    const { displayName, phoneNumber } = req.body;
    const userId = req.user?.uid;
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    try {
        const admin = await setupFirebaseAdmin();

        // Update user information in Firebase
        const updatedUser = await admin.auth().updateUser(userId, {
            displayName,
            // phoneNumber,
        });

        res.status(200).json({
            message: "Profile updated successfully",
            profile: {
                displayName: updatedUser.displayName,
                email: updatedUser.email,
                // phoneNumber: updatedUser.phoneNumber,
            },
        });
    } catch (error) {
        console.error("Error updating user profile:", error);
        res.status(500).json({ message: "Failed to update profile", error });
    }
});


// Delete a user
router.delete("/users/:uid", async (req, res) => {
    const { uid } = req.params;

    try {
        const admin = await setupFirebaseAdmin();

        // Delete the user by UID
        await admin.auth().deleteUser(uid);

        res.status(200).json({ status: true, message: "User deleted successfully" });
    } catch (error) {
        console.error("Error deleting user:", error);
        res.status(500).json({ status: false, message: "Failed to delete user", error });
    }
});

// Dropbox Routes
router.post('/dropbox/authorise',initiateDropBoxAuth);
router.post('/dropbox/reauthorise',reauthoriseDropboxAuth);
// router.get('/dropbox/callback', dropboxCallback);
router.get('/dropbox/callback', oAuthDropboxCallback);



// Google Drive Routes
router.post('/googledrive/authorise', initiateGoogleAuth);
router.post('/googledrive/reauthorise', reauthoriseGoogleAuth);
router.get('/googledrive/oauth2Callback', oAuthCallBack);

//New Connection
// Generate OAuth link
router.post("/link",async(req, res) => {
    const { provider} = req.query;
    const { uid} = req.body;
    let authUrl

    if (provider === "google") 
        authUrl = await generateAuthLink(uid)

    else if (provider === "dropbox") 
        authUrl = await generateDropboxAuthLink(uid)

    else 
        return res.status(400).send({ success: false, message: "Invalid provider" });
    

    res.status(200).json(authUrl)

})




//Account Drive with Files (using)
router.post('/googledrive', async (req, res) => {
    const { uid } = req.body;
    const data = await listAllDriveWithFiles(uid);
    res.status(200).json({
        success: data?.success,
        message: data.message,
        data: data.data
    });
});





router.post('/googledrive/all', async (req, res) => {
    const { uid } = req.body;
    const data = await fetchAllGoogleDriveFiles(uid);
    res.status(200).json({
        success: data?.success,
        message: data.message,
        data: data.data
    });
});

router.post('/googledrive/search', async (req, res) => {
    const { uid, folderId } = req.body;
    const data = await fetchFilesByGoogleFolder(folderId, uid);
    res.status(200).json({
        success: data?.success,
        message: data.message,
        data: data.data
    });
});

//Get Specific drive status
router.get('/googledrive/getdrive', async (req, res) => {
    const data = await googleDriveStatus(req.query.id);
    res.status(200).json({
        success: data?.success,
        message: data.message,
        data: data.data
    });
});


//Get All Google Drive status
router.post('/googledrive/drives', async (req, res) => {
    const { uid } = req.body;
    const data = await fetchGoogleDriveStatus(uid);
    res.status(200).json({
        success: data?.success,
        message: data.message,
        data: data.data
    });
});






module.exports = router;
