const express = require('express')
const mongoose = require('mongoose')

const {


    getAccountById,
    getAccounts,
    createAccount,
    setAccountVisibility,
    setAccountStatus,
} = require('../controllers/accountsController')

const router = express.Router()




// only used in development
// GET Methods
router.post('/', getAccounts); 
router.post('/create', createAccount);
//POST methods
router.post('/:id', async(req,res)=> {
    let data = await getAccountById(req.params.id)
    return res.json(data)
});  //Used in development

//Update Methods (update without receiving any data from frontend)
router.put('/set-status', setAccountStatus);
router.put('/set-visibility', setAccountVisibility);



module.exports = router;