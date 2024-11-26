const express = require('express');
const mongoose = require('mongoose');
const { 
    createCredential, 
    getAllCredentials, 
    getCredentialById, 
    updateCredentialByProvider, 
    deleteCredential, 
    checkCredentials, 
    deleteAllCredential, 
    checkConfig, 
    setCredential, 
    getFirebaseConfig, 
    checkUserPermission, 
    setPlatformAdmin, 
    getCloudCredentials 
} = require('../controllers/credentialsController');
const router = express.Router()


//check all credential, return boolean of credential
router.get('/check', async (req, res) => {
    const response = await checkCredentials();
    res.status(200).json(response);
});

// check status firebase and status of all cloud credential, return status and remark
// if one of the credential be inserted, then status of cloud credential will be true
router.get('/check/config', async (req, res) => {
    try {
        const response = await checkConfig();
        res.status(200).json(response);
    } catch (error) {
        console.error("Error in /check/config route:", error.message);
        res.status(500).json({
            status: false,
            remark: "Failed to check or create configuration",
            error: error.message,
        });
    }
});

//Check cloud credential, return provider,status, and remark
router.get('/cloudConfig', getCloudCredentials);


//sensitive update
router.post('/update', async (req, res) => {
    const { credential, provider, type } = req.body;
    const response = await setCredential(provider, type, credential);
    res.status(200).json(response);
});
//sensitive data
router.post('/firebaseConfig', async (req, res) => {
    const data = await getFirebaseConfig();
    res.status(200).json(data);
});
//check user permission, return: true or false
router.post('/platformConfig', async (req, res) => {
    const { uid } = req.body;
    const data = await checkUserPermission(uid);
    res.status(200).json(data);
});
//update user id
router.put('/platformConfig/admin', async (req, res) => {
    const { admin } = req.body;
    if (!admin) return res.status(400).json({ success: false, message: "User missing" });
    
    const data = await setPlatformAdmin(admin.toString());
    if (data.success)
        res.status(200).json(data);
    else 
        res.status(500).json(data);
    
});


//only used in development
router.get('/', getAllCredentials);
router.get('/:id', async (req, res) => {
    const response = await getCredentialById(req.params.id);
    res.status(200).json(response);
});
router.post('/', createCredential);
router.put('/:id', updateCredentialByProvider);
router.delete('/:id', deleteCredential);
router.post('/deleteAll', deleteAllCredential);


module.exports = router;
