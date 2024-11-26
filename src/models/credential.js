// src/models/credentialModel.js

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Credential schema
const Credential = mongoose.models.Credential || mongoose.model('Credential', new Schema({
    provider:       {type: String,required: true,},
    type:           {type: String,required: true,},
    credential:     {type: String,required: true,},
    metadata:       {type: Object,},
    createdAt:      {type: Date,default: Date.now,},
    updatedAt:      {type: Date,default: Date.now,},
}));

// Automatically update the `updatedAt` field before saving
Credential.schema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = Credential
