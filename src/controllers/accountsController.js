const { Request, Response } = require('express');
const mongoose = require('mongoose');
const url = require('url');

const Credential  = require('../models/credential');
const { encrypt,decrypt } = require('../utils/encryption');
const Account  = require('../models/Account');
const { google } = require('googleapis');

const createAccount = async (req, res) => {
    try {
        var {
            credentialId,
            uid,
            tokens,
            isActive,
            isPublic,
            isAuthorized,
            email
        } = req.body;

        if (!credentialId) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
        }

        const encryptedTokens = encrypt(JSON.stringify(tokens));
        const newsavedAccount = new Account({
            credentialId: credentialId,
            uid: uid,
            tokens: encryptedTokens,
            isActive: isActive,
            isPublic: isPublic,
            isAuthorized: isAuthorized,
            email: email
        });

        const savedAccount = await newsavedAccount.save();
        return res.status(201).json({
            success: true,
            message: 'Account created successfully',
            savedAccount
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: `Server Error. Error: ${error.message}`
        });
    }
};

const editAccount = async(id,data)=>{
    //find aacount
    let q = await Account.findById(id)
    if(!q) return false

    //Update data if exist
    q.credentialId  = data.credentialId? data.credentialId : q.credentialId
    q.tokens        = data.tokens? encrypt(JSON.stringify(data.tokens)) : data.tokens
    q.email         = data.email? data.email : q.email
    q.isActive      = data.isActive? data.isActive : q.isActive
    q.isPublic      = data.isPublic? data.isPublic : q.isPublic
    q.isAuthorized  = data.isAuthorized? data.isPublic : q.isAuthorized

    //Save data
    await q.save()
    return true
}

const deleteAccount = async(id)=>{
    try {
        const result = await Account.deleteOne(id)
        console.log(`${result.deletedCount} accounts deleted with id: ${id}`);
        return true
    } catch (error) {
        console.error(`Error deleting accounts with id ${id}`)
        throw error;
    }
}



// Get all Accounts
 const getAccounts = async (req,res) => {
    try {
        const {uid} = req.body
        const q = await Account.find({
            $or: [
                { isPublic: true, isActive: true, isAuthorized: true, },
                { uid:uid }
            ]
        }).populate({path:'credentialId',select:'provider'})
        
        const accounts = q.map((account)=>{
            let token = `${(account.tokens).substring(0,5)}...${(account.tokens).substring(150,155)}...${(account.tokens).substring(account.tokens.length-4)}`
            return {
                _id: account._id ,  // Encrypted _id
                email: account.email,
                provider: account.credentialId.provider, // Accessing from Credential model
                uid:account.uid,
                token:token,
                isAuthorized: account.isAuthorized,
                isActive: account.isActive,
                isPublic: account.isPublic
            }
        })
        return res.status(200).json({data:accounts || {}})
    } catch (error) {
        console.error(`Error retrive accounts. Error:${error.message}`)
        throw error;
    }
};




//Used to fetch all accounts by using ID from frontend
const fetchAndTransformData = async(userID) =>{
    let data = {}
    try {
        const accounts = await Account.find({

            $or:[ {isPublic:true},{uid:userID} ]

        }).populate({path:'credentialId',select:'provider'});
        


        if (!accounts) return {success:false,message:"Accounts not found",data}
    
        const transformedAccounts = accounts.map( account =>{
            if (!(account.credentialId instanceof mongoose.Types.ObjectId)) {
                const concatenatedData = {
                    accountId:account._id,
                    uid:userID,
                    credentialId:account.credentialId
                }
                let decryptedToken = JSON.parse(decrypt(account.tokens))
                let access_token = `${(decryptedToken.access_token).substring(0,5)}...${(decryptedToken.access_token).substring(150,155)}...${(decryptedToken.access_token).substring(decryptedToken.access_token.length-4)}`
                account.save()

                data = {
                    _id: account.tempToken ,  // Encrypted _id
                    email: account.email,
                    provider: account.credentialId.provider, // Accessing from Credential model
                    token:access_token,
                    isAuthorized: account.isAuthorized,
                    isActive: account.isActive,
                    isPublic: account.isPublic
                }

                return {
                    success:true,
                    message:'Acquired account successfully',
                    data
                };
             
            }else{
                return {
                    success:false,
                    message:'Credential is not populated',
                    data
                };
            } 
        })
        return transformedAccounts
        
        // return res.status(200).json({ transformedAccounts });
    } catch (error) {
        return { success:false,message: `Error fetching and transforming data. \n Error: ${error.message}`,data};
    }
}


//Regenerate token (Generate temporary id, token)
 const generateIdToken = (old_token) => {
    let decomposedToken = JSON.parse(decrypt(old_token))
    const token = encrypt({
        accountId:decomposedToken.accountId,
        uid:decomposedToken.uid,
        credentialId:decomposedToken.credentialId
    })

    return token
}


// Get a Account by ID
 const getAccountById = async (id) => {
    try{
        let q = await Account.findById(id);
        if (!q){
            console.error(`Account ${id} not found`)
            return {}
        }
        q.tokens = JSON.parse(decrypt(q.tokens))
        let tokens = JSON.parse(decrypt(q.tokens))

        return {q,tokens}
    
    } catch (error) {
        console.log(`Server Error. Error: ${(error).message }`)
        throw error
        // return res.status(500).json({
        //     success:false, 
        //     message: `Server Error. Error: ${(error).message }`
        // });
    }
};


 const findAccountById = async(id)=>{
    try{
        let q = await Account.findById(id)
        if (!q) return false

        return {
            id: q._id,
            credentialId:q.credentialId.toString(),
            email:q.email,
            token:JSON.parse(decrypt(q.tokens)),
            isActive: q.isActive,
            isAuthorized:q.isAuthorized,
            isPublic:q.isPublic,
        };
    }catch(error){
        console.log(`An error occurred while fetching account. Error:${error.message}`)
        throw error   
    }
}

 const findAccountByEmail = async(email)=>{
    try{
        let q = await Account.findOne({email:email})
        if (!q) return false

        return {
            id: q._id,
            credentialId:q.credentialId.toString(),
            email:q.email,
            token:JSON.parse(decrypt(q.tokens)),
            isActive: q.isActive,
            isAuthorized:q.isAuthorized,
            isPublic:q.isPublic,
        };
    }catch(error){
        console.log(`An error occurred while fetching account. Error:${error.message}`)
        throw error
    }
}






 const setAccountStatus  = async (req, res) => {
    const {id,uid} = req.body
    try {

        const account = await Account.findOne({uid:uid,_id:id});
        
        if(!account) return res.status(404).json({status:false,message:"Account not found"}) 
        account.isActive = !account.isActive
        await account.save()
        
        return res.status(200).json({status:true,message:`Account ${id} status updated`});
    } catch (error) {
        return res.status(500).json({ status:false,message: "Failed to update account status", error });
    }

}
 const setAccountVisibility  = async (req, res) => {
    const {id,uid} = req.body
    try {
        // Fetch the account by ID
        const account = await Account.findOne({_id:id});
        
        if(!account) 
            return res.status(404).json({status:false,message:"Account not found"}) 
        
        if(account.uid !== uid)
            return res.status(401).json({status:false,message:`You are not allow to change the status of Account.`})
        
        account.isPublic = !account.isPublic
        await account.save()
        
        return res.status(200).json({status:true,message:`Account status updated`});
    } catch (error) {
        return res.status(500).json({ status:false,message: `Failed to update account status ${error.message}` });
    }

}


module.exports = {
    createAccount,
    getAccounts,
    generateIdToken,
    getAccountById,
    findAccountById,
    findAccountByEmail,

    setAccountStatus,
    setAccountVisibility

};
