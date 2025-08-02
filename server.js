const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const base64url = require('base64url');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:8080'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// In-memory storage (replace with database in production)
const users = new Map();
const challenges = new Map();
const credentials = new Map();

// Helper functions
function generateChallenge() {
    return crypto.randomBytes(32);
}

function generateUserId() {
    return crypto.randomBytes(16);
}

// RP (Relying Party) configuration
const rpConfig = {
    name: process.env.RP_NAME || 'Passkey Authentication System',
    id: process.env.RP_ID || 'localhost', // Change this for production
    origin: process.env.ORIGIN || 'http://localhost:3000'
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Registration routes
app.post('/api/register/begin', (req, res) => {
    try {
        const { username, email, displayName } = req.body;

        if (!username || !email || !displayName) {
            return res.status(400).json({ error: 'Username, email, and display name are required' });
        }

        // Check if user already exists
        if (users.has(username)) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const challenge = generateChallenge();
        const userId = generateUserId();

        // Store challenge temporarily
        challenges.set(username, {
            challenge: challenge,
            userId: userId,
            timestamp: Date.now()
        });

        const registrationOptions = {
            challenge: base64url.encode(challenge),
            rp: {
                name: rpConfig.name,
                id: rpConfig.id
            },
            user: {
                id: base64url.encode(userId),
                name: username,
                displayName: displayName
            },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" }, // ES256
                { alg: -257, type: "public-key" } // RS256
            ],
            authenticatorSelection: {
                authenticatorAttachment: "platform",
                userVerification: "preferred",
                requireResidentKey: false
            },
            timeout: 60000,
            attestation: "none"
        };

        res.json(registrationOptions);
    } catch (error) {
        console.error('Registration begin error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/register/complete', (req, res) => {
    try {
        const { username, credential } = req.body;

        if (!username || !credential) {
            return res.status(400).json({ error: 'Username and credential are required' });
        }

        // Get stored challenge
        const challengeData = challenges.get(username);
        if (!challengeData) {
            return res.status(400).json({ error: 'No registration in progress' });
        }

        // Check challenge timeout (5 minutes)
        if (Date.now() - challengeData.timestamp > 300000) {
            challenges.delete(username);
            return res.status(400).json({ error: 'Registration timeout' });
        }

        // Basic verification (in production, use proper WebAuthn library)
        const clientDataJSON = JSON.parse(base64url.decode(credential.response.clientDataJSON));

        // Verify challenge
        const receivedChallenge = base64url.toBuffer(clientDataJSON.challenge);
        if (!challengeData.challenge.equals(receivedChallenge)) {
            return res.status(400).json({ error: 'Challenge mismatch' });
        }

        // Verify origin
        if (clientDataJSON.origin !== rpConfig.origin) {
            return res.status(400).json({ error: 'Origin mismatch' });
        }

        // Store user and credential
        const user = {
            id: challengeData.userId,
            username: username,
            email: req.body.email || username + '@example.com',
            displayName: clientDataJSON.displayName || username,
            createdAt: new Date().toISOString()
        };

        users.set(username, user);
        credentials.set(credential.id, {
            credentialId: credential.id,
            credentialPublicKey: credential.response.attestationObject, // Store properly in production
            counter: 0,
            username: username
        });

        // Clean up challenge
        challenges.delete(username);

        res.json({
            success: true,
            user: {
                username: user.username,
                displayName: user.displayName,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration complete error:', error);
        res.status(500).json({ error: 'Registration verification failed' });
    }
});

// Authentication routes
app.post('/api/authenticate/begin', (req, res) => {
    try {
        const { username } = req.body;
        const challenge = generateChallenge();

        let allowCredentials = undefined;

        if (username) {
            // Username provided - get user's credentials
            const user = users.get(username);
            if (!user) {
                return res.status(400).json({ error: 'User not found' });
            }

            // Find credentials for this user
            allowCredentials = [];
            for (const [credId, credData] of credentials.entries()) {
                if (credData.username === username) {
                    allowCredentials.push({
                        id: credId,
                        type: "public-key",
                        transports: ["internal", "hybrid"]
                    });
                }
            }

            if (allowCredentials.length === 0) {
                return res.status(400).json({ error: 'No credentials found for user' });
            }
        }

        // Store challenge
        const challengeKey = username || 'anonymous_' + Date.now();
        challenges.set(challengeKey, {
            challenge: challenge,
            username: username,
            timestamp: Date.now()
        });

        const authenticationOptions = {
            challenge: base64url.encode(challenge),
            timeout: 60000,
            rpId: rpConfig.id,
            allowCredentials: allowCredentials,
            userVerification: "preferred"
        };

        res.json(authenticationOptions);
    } catch (error) {
        console.error('Authentication begin error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/authenticate/complete', (req, res) => {
    try {
        const { username, assertion } = req.body;

        if (!assertion) {
            return res.status(400).json({ error: 'Assertion is required' });
        }

        // Find the challenge
        let challengeData = null;
        let challengeKey = null;

        if (username) {
            challengeKey = username;
            challengeData = challenges.get(username);
        } else {
            // Find anonymous challenge by looking for recent ones
            for (const [key, data] of challenges.entries()) {
                if (key.startsWith('anonymous_') && Date.now() - data.timestamp < 300000) {
                    challengeKey = key;
                    challengeData = data;
                    break;
                }
            }
        }

        if (!challengeData) {
            return res.status(400).json({ error: 'No authentication in progress' });
        }

        // Check timeout
        if (Date.now() - challengeData.timestamp > 300000) {
            challenges.delete(challengeKey);
            return res.status(400).json({ error: 'Authentication timeout' });
        }

        // Get credential data
        const credentialData = credentials.get(assertion.id);
        if (!credentialData) {
            return res.status(400).json({ error: 'Credential not found' });
        }

        // Get user data
        const user = users.get(credentialData.username);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        // Basic verification (in production, use proper WebAuthn library)
        const clientDataJSON = JSON.parse(base64url.decode(assertion.response.clientDataJSON));

        // Verify challenge
        const receivedChallenge = base64url.toBuffer(clientDataJSON.challenge);
        if (!challengeData.challenge.equals(receivedChallenge)) {
            return res.status(400).json({ error: 'Challenge mismatch' });
        }

        // Verify origin
        if (clientDataJSON.origin !== rpConfig.origin) {
            return res.status(400).json({ error: 'Origin mismatch' });
        }

        // Update counter (basic implementation)
        credentialData.counter++;
        credentialData.lastUsed = new Date().toISOString();

        // Clean up challenge
        challenges.delete(challengeKey);

        res.json({
            success: true,
            user: {
                username: user.username,
                displayName: user.displayName,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Authentication complete error:', error);
        res.status(500).json({ error: 'Authentication verification failed' });
    }
});

// Debug routes (remove in production)
if (process.env.NODE_ENV !== 'production') {
    app.get('/api/debug/users', (req, res) => {
        const userList = Array.from(users.values()).map(user => ({
            username: user.username,
            displayName: user.displayName,
            email: user.email,
            createdAt: user.createdAt
        }));
        res.json(userList);
    });

    app.get('/api/debug/credentials', (req, res) => {
        const credList = Array.from(credentials.values()).map(cred => ({
            credentialId: cred.credentialId.substring(0, 20) + '...',
            username: cred.username,
            counter: cred.counter,
            lastUsed: cred.lastUsed
        }));
        res.json(credList);
    });
}

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Cleanup old challenges periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, data] of challenges.entries()) {
        if (now - data.timestamp > 300000) { // 5 minutes
            challenges.delete(key);
        }
    }
}, 60000); // Clean every minute

app.listen(PORT, () => {
    console.log(`🚀 Passkey Authentication Server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🌐 RP ID: ${rpConfig.id}`);
    console.log(`🎯 Origin: ${rpConfig.origin}`);

    if (process.env.NODE_ENV !== 'production') {
        console.log(`🔍 Debug endpoints available:`);
        console.log(`   GET /api/debug/users`);
        console.log(`   GET /api/debug/credentials`);
    }
});

module.exports = app;