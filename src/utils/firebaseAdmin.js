const admin = require("firebase-admin");
const Credential = require("../models/credential");
const {decrypt} = require("./encryption");

let firebaseAdminInitialized = false;

async function setupFirebaseAdmin() {
    if (firebaseAdminInitialized) {
        console.log("Firebase Admin SDK is already initialized.");
        return admin;
    }

    // Fetch credential from database
    const q = await Credential.findOne({ provider: "firebase", type: "auth" });
    if (!q) {
        throw new Error("Firebase credential not found");
    }

    const credential = JSON.parse(decrypt(q.credential));
    const serviceAccount = credential.serviceAccount;

    // Initialize Firebase Admin SDK
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });

    console.log("Firebase Admin SDK initialized successfully");
    firebaseAdminInitialized = true;

    return admin;
}

module.exports = setupFirebaseAdmin;
