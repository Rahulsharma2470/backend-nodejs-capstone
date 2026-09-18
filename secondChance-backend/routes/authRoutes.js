const express = require('express');
const router = express.Router();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const logger = require('../logger');

const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to secondChance database
        const db = await connectToDatabase();

        // Task 2: Access users collection
        const collection = db.collection("users");

        // Task 3: Check if email already exists
        const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }

        // Task 4: Hash the password
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);

        // Task 5: Insert the user
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });

        // Task 6: Create JWT authentication
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        const authtoken = jwt.sign(payload, JWT_SECRET);

        // Task 7: Log successful registration
        logger.info(`User registered successfully: ${req.body.email}`);

        // Task 8: Return email and token
        res.status(200).json({
            email: req.body.email,
            token: authtoken
        });

    } catch (e) {
        logger.error(`Registration error: ${e}`);
        return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        const db = await connectToDatabase();
        const collection = db.collection("users");

        const theUser = await collection.findOne({
            email: req.body.email
        });

        if (theUser) {
            const result = await bcryptjs.compare(
                req.body.password,
                theUser.password
            );

            if (!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong password' });
            }

            const userName = theUser.firstName;
            const userEmail = theUser.email;

            const payload = {
                user: {
                    id: theUser._id.toString()
                }
            };

            const authtoken = jwt.sign(payload, JWT_SECRET);

            return res.json({
                authtoken,
                userName,
                userEmail
            });
        }

        logger.error('User not found');
        return res.status(404).json({ error: 'User not found' });

    } catch (e) {
        logger.error(`Login error: ${e}`);
        return res.status(500).send('Internal server error');
    }
});

router.put('/update', async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        logger.error('Validation errors in update request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const email = req.headers.email;

        if (!email) {
            logger.error('Email not found in the request headers');
            return res.status(400).json({
                error: "Email not found in the request headers"
            });
        }

        const db = await connectToDatabase();
        const collection = db.collection("users");

        const existingUser = await collection.findOne({ email });

        if (!existingUser) {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        if (req.body.firstName) {
            existingUser.firstName = req.body.firstName;
        }

        if (req.body.lastName) {
            existingUser.lastName = req.body.lastName;
        }

        if (req.body.password) {
            const salt = await bcryptjs.genSalt(10);
            existingUser.password = await bcryptjs.hash(req.body.password, salt);
        }

        existingUser.updatedAt = new Date();

        const updatedUser = await collection.findOneAndUpdate(
            { email },
            { $set: existingUser },
            { returnDocument: 'after' }
        );

        const payload = {
            user: {
                id: updatedUser._id.toString(),
            },
        };

        const authtoken = jwt.sign(payload, JWT_SECRET);

        res.json({ authtoken });

    } catch (e) {
        logger.error(`Update error: ${e}`);
        return res.status(500).send('Internal server error');
    }
});


module.exports = router;