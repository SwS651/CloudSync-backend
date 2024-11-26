// src/models/accountModel.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Account schema
const Account = mongoose.models.Account || mongoose.model('Account',new Schema({
    credentialId:   {type: Schema.Types.ObjectId,ref: 'Credential',required: true,},
    uid:            {type: String,required: true},
    provider:       {type: String,required: true},
    tokens:         {type: String,required: true,},
    email:          {type: String,},
    isActive:       {type: Boolean,default: true,},
    isPublic:       {type: Boolean,default: false,},
    isAuthorized:   {type: Boolean,default: false,},
    createdAt:      {type: Date,default: Date.now,},
    updatedAt:      {type: Date, default: Date.now,},
}));


// Helper function to update `updatedAt` field
function updateUpdatedAt(next) {
    this.updatedAt = Date.now();
    next();
}
Account.schema.pre('save', updateUpdatedAt);
Account.schema.pre('findOneAndUpdate', updateUpdatedAt);
Account.schema.pre('updateOne', updateUpdatedAt);
Account.schema.pre('updateMany', updateUpdatedAt); 


module.exports = Account