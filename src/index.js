// src/index.js

const mongoose = require('mongoose');

const express = require('express');
const dotenv = require('dotenv')
const cors = require('cors')
dotenv.config();

const credentialRoutes = require( './routes/credentials');
const accountRoutes = require( './routes/accounts');
const authRoutes = require( './routes/auth');
const cloudRoutes = require( './routes/cloudDrive');

const JWT_SECRET = process.env.JWT_SECRET || 'default_jwt_secret_key';
const MONGO_URI = process.env.MONGO_URI
const port = process.env.PORT || 3000;

// const itemRoutes = require('./routes/itemRoutes');

const app = express();
const PORT = 3000;


// Middleware to parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Enable CORS for your frontend
const corsOptions = {
    origin: 'http://localhost:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};
app.use(cors(corsOptions));

mongoose.connect(MONGO_URI)
.then(async () => {
    console.log('Connected to MongoDB');
})
.catch((error) => console.error('MongoDB connection error:', error));



// Set up item routes with the base path `/api/items`
// app.use('/', async(req, res) => {
//     res.send({ message: 'Secure Data' });
//   });
app.use('/api/auth', authRoutes);
app.use('/api/credentials', credentialRoutes);
// app.get('/api/cloudConfig', getCloudCredentials);
app.use('/api/accounts', accountRoutes);
app.use('/api/cloud', cloudRoutes);

// Start the server

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});