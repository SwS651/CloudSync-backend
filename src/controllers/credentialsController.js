const { Request, Response } = require('express');
const Credential  = require('../models/credential');
// const {revokeAccounts}  = require('../controllers/cloudAPIControllers/googleDriveController');
const {encrypt, decrypt} = require('../utils/encryption');
const mongoose = require('mongoose');

//Default Credentials
 const defaultConfig = () => {
    return {
        provider: "config",
        type: "config",
        credential: encrypt(JSON.stringify({ platform: "CloudSync", admin: "" })),
        metadata: {
            status: false,
            remark: "Project setup is not complete yet"
        },
        createdAt: new Date(),
        updatedAt: new Date()
    };
}
 const defaultCredential = (name, type) => {
    return {
        provider: name,
        type: type,
        credential: encrypt(JSON.stringify({ NA: "NA" })),
        metadata: {
            status: false,
            remark: `Empty`
        },
        createdAt: new Date(),
        updatedAt: new Date()
    };
};

// Check and Create Credentials Atomically
const ensureCredentialExists = async (provider, defaultDataGenerator) => {
    try {
        let credential = await Credential.findOne({ provider });
        if (!credential) {
            credential = await Credential.create(defaultDataGenerator());
            console.log(`Default ${provider} credential created.`);
        }
        return credential;
    } catch (error) {
        console.error(`Error ensuring ${provider} credential:`, error.message);
        throw new Error(`Failed to ensure ${provider} credential`);
    }
};

// LV 3 Methods
// Check credential, if there is any new credential, create it as default here
const checkCredentials = async () => {
    // let creAuth, creGoogle, creConfig = null;

    // //Find credential
    // creAuth     = await Credential.findOne({ provider: "firebase" });
    // creGoogle   = await Credential.findOne({ provider: "google" });
    // creDropbox   = await Credential.findOne({ provider: "dropbox" });
    // creConfig   = await Credential.findOne({ provider: "config" });

    // creAuth     = (!creAuth)   ? await Credential.create(defaultCredential("firebase", "auth")) : creAuth;
    // creGoogle   = (!creGoogle) ? await Credential.create(defaultCredential("google", "cloudAPI")) : creGoogle;
    // creDropbox   = (!creDropbox) ? await Credential.create(defaultCredential("dropbox", "cloudAPI")) : creDropbox;
    // creConfig   = (!creConfig) ? await Credential.create(defaultConfig()) : creConfig;
    // Ensure all required credentials exist
    const [creAuth, creGoogle, creDropbox, creConfig] = await Promise.all([
        ensureCredentialExists("firebase", () => defaultCredential("firebase", "auth")),
        ensureCredentialExists("google", () => defaultCredential("google", "cloudAPI")),
        ensureCredentialExists("dropbox", () => defaultCredential("dropbox", "cloudAPI")),
        ensureCredentialExists("config", defaultConfig),
    ]);
    return {
        firebase : (creAuth?.metadata.status   || false),
        google   : (creGoogle?.metadata.status || false),
        dropbox  : (creDropbox?.metadata.status || false),
        config   : (creConfig?.metadata.status || false)
    };
}

const checkConfig = async () => {
    let q = await checkCredentials();
    let cloudStatus = await checkCloudConfig()

    if (!q.firebase && !cloudStatus)
        return { status: false, remark: "Platform should be configured" };
    
    const configCre = await Credential.findOne({ provider: "config", type: "config" });
    const credentialData = JSON.parse(decrypt(configCre.credential));

    if (credentialData.admin !== "" && configCre.metadata.status !== true) {
        configCre.metadata = { status: true, remark: "Configured" };
        await configCre.save();
    }

    return configCre.metadata;
};

//LV 2 Methods
const checkCloudConfig = async() => {
    const q = await Credential.find({type:'cloudAPI'})
    if (!q) return false
    let status = false

    await Promise.all(q.map((credential)=>{
        if(credential.metadata.status === true)
            status = true
            return
    }))
    return status
}


// Get Sentive data from credential
const findCredentialByCloudAPI = async(provider)=> {
    let q = await Credential.findOne({provider:provider})
    if (!q) return false
    try {
        // Switch to handle different provider cases
        switch (provider) {
            case "google":
                let credential = JSON.parse(decrypt(q.credential));
                return credential.installed || credential.web;

            case "dropbox":
                // Add logic specific to Dropbox if needed
                let dropboxCredential = JSON.parse(decrypt(q.credential));
                return dropboxCredential;

            default:
                // Handle unsupported providers
                console.error(`Unsupported provider: ${provider}`);
                return false
        }
    } catch (error) {
        // Log the error for debugging purposes
        console.error(`Error in findCredentialByCloudAPI: ${error.message}`);
        return false;
    }
}

//Lv 3: but sentive data
const getFirebaseConfig = async() =>{
    let q = await Credential.findOne({provider:"firebase",type:"auth"})
    if(!q) return {status:false,message:"Firebase credential not found"}

    const credential = JSON.parse(decrypt(q.credential))
    return {status:true,message:"Get Firebase credential",data:credential.firebaseSDK}
}

const checkUserPermission = async(uid)=>{
    let q = await Credential.findOne({provider:"config",type:"config"})

    let credential = JSON.parse(decrypt(q.credential))
    if (credential.admin===uid)
        return {status:true}
    else
        return {status:false}
}
 const getCloudCredentials = async (req, res) => {
    try {
      let q = await Credential.find({ type: "cloudAPI" });
      if (!q || q.length === 0) {
        return res.status(404).json({ status: false, message: "Credentials not found" });
      }
      const credentials = await Promise.all(q.map(async (credential) => {
        return {
          provider: credential.provider,
          status: credential?.metadata.status,
          remark:credential.metadata.remark
        };
      }));
      return res.status(200).json({ status:true, credentials });
    } catch (error) {
      return res.status(500).json({ status: false, message: `An error occurred: ${(error).message}` });
    }
}  
//lv3: sentive update
 const setCredential = async(provider,type,credential)=>{
    let q = await Credential.findOne({provider:provider,type:type})
    q = !q? await Credential.create(defaultCredential(provider,type)): q
   
    q.credential = encrypt(credential)
    q.metadata = {status:true,remark:"Inserted"}
    await q.save()

    if(q.type==="cloudAPI" && q.provider==="google")
        await revokeAccounts(q._id)

    return {success:true,message:"Set credential successfully"}
}


 const setPlatformAdmin = async(admin)=>{
    let q = await Credential.findOne({provider:"config",type:"config"})
    if(!q) return {success:false,message:"Platform credential not found"}

    let credential = JSON.parse(decrypt(q.credential))
    credential.admin = admin
    q.credential = encrypt(credential)
    await q.save()
    return {success:true,message:"Set user successfully"}
}



// Create a new credential
 const createCredential = async (req, res) => {
  
    try {
        var { provider,type,metadata, credential } = req.body;

        if (!provider ||!type || !credential) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        credential = (typeof credential === 'string')? JSON.parse(credential) : credential
        

        credential = encrypt(JSON.stringify(credential));

        const newCredential = new Credential({
            provider,
            credential,
        });

        await newCredential.save();

        return res.status(201).json({
            success:true,
            message: 'Credential uploaded successfully',
        });
    } catch (error) {

        return res.status(500).json({ 
            success:false,
            message: `Server Error:${(error).message }`, 
        });

    }
};

// Get all credentials
 const getAllCredentials = async (req, res) => {
    try {
        const credentials = await Credential.find();
        if (credentials.length === 0) 
        return res.status(404).json({ success: false, message:"Credentials not found" });

        return res.status(200).json({ success: true, data: credentials });
    } catch (error) {
        
        return res.status(500).json({ 
            success: false,
            message: `An error occurred while retrieving credentials. Error:  ${(error).message}`,
        });
    }
};
// Get a single credential by ID
 const getCredentialById = async(id) =>{
    try{
        let q = await Credential.findById(id)

        if (!q) 
        return { 
            success:false,
            message: 'Credential not found' ,
        };
        const decryptedCredential = JSON.parse(decrypt(q.credential))
        // const { client_id, client_secret, redirect_uris } = credential.installed || credential.web;
            
        return { 
            success:true,
            data:{
                provider:q.provider,
                type:q.type,
                credential:decryptedCredential,
                metadata:q.metadata,
                createAt:q.createdAt,
                updateAt:q.updatedAt
            }
        };

    }catch(error){
        return { 
            success:false,
            message: error.message,
        };
    }
}


 const getCredentialByProvider = async(provider) =>{
    try{
        let q = await Credential.findOne({provider:provider})

        if (!q) 
        return { 
            success:false,
            message: 'Credential not found'
        };

        const decryptedCredential = JSON.parse(decrypt(q.credential))
        // const { client_id, client_secret, redirect_uris } = credential.installed || credential.web;
            
        return { 
            success:true,
            data:{
                provider:q.provider,
                type:q.type,
                credential:decryptedCredential,
                metadata:q.metadata,
                createAt:q.createdAt,
                updateAt:q.updatedAt
            }
        };
    }catch(error){
        return { 
            success:false,
            message: error.message,
        };
    }
}



// Update a credential by ID, only used in development
 const updateCredentialByProvider = async (req, res) => {
    try {
        const { provider,credential } = req.body;
        const q = await Credential.findOne({provider:provider});

        if (!q) return res.status(404).json({ success:false,message: 'Credential not found' });

        if(q.type === 'cloudAPI' || q.type ==='auth')
        return res.status(405).json({ 
            success:false,message: 'Credentials cannot be updated here, please use another method' });

        //Update credential if exist
        q.credential = !credential? encrypt(JSON.stringify(credential)): q.credential
        await q.save()

        res.status(200).json({ 
            success:true,
            message: 'Credential updated successfully'
        });

    } catch (error) {
        return res.status(500).json({ 
            success:false,
            message: `Server Error. ${ (error).message }`
        });
    }
};


// LV 1 Methods (or used in development)
// Delete a credential by ID
 const deleteCredential = async (req, res) => {
    try {
        const deletedCredential = await Credential.findByIdAndDelete(req.params.id);
        if (!deletedCredential) {
            return res.status(404).json({ success: false, message: 'Credential not found' });
        }
        res.status(200).json({success: true,  message: 'Credential deleted successfully' });
    } catch (error) {
        return res.status(500).json({ 
            success: false,
            message: `Server Error: ${(error).message}` 
        });
    }
};
// Delete a credential by ID
 const deleteAllCredential = async (req, res) => {
    try {
        await Credential.deleteMany({})
        return res.status(200).json({success: true,  message: 'Credential deleted successfully' });
        
    } catch (error) {
        return res.status(500).json({ 
            success: false,
            message: `Server Error: ${(error).message}` 
        });
    }
};


//check Admin 
const authoriseToken = async (req,res,next)=>{
    const q = await Credential.findOne({provider:'config',type:'config'})
    if (!q) return false
    let config = JSON.parse(decrypt(config.credential))
    if (req.body.token.toString() === config.admin)
        next()

    return res.status(401).json({message:'Access Denied'})
}

//Check User
const authenticateToken = async (req,res,next)=>{
    //Implement something here
    return res.status(401).json({message:'Access Forbidden: Insufficient Permissions'})
}


module.exports = {
    checkCredentials,
    checkConfig,
    checkUserPermission,
    getFirebaseConfig,
    getCloudCredentials,
    setCredential,
    setPlatformAdmin,
    
    createCredential,
    getAllCredentials,
    getCredentialById,
    getCredentialByProvider,
    updateCredentialByProvider,



    
    //For internal use
    authoriseToken,
    findCredentialByCloudAPI,
    
    deleteCredential,
    deleteAllCredential,


    defaultConfig,
    defaultCredential

}
