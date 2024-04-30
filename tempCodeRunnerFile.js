const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const cors = require('cors');

const app = express();
const port = 4000;

app.use(cors()); // Enable CORS for all routes
app.use(express.json());

mongoose.connect('mongodb+srv://SumitSingh:SumitSingh@teabooking.fnx0evo.mongodb.net/TeaBooking')
.then(() => {
  console.log('Connected to MongoDB');
})
.catch((error) => {
  console.error('Error connecting to MongoDB:', error);
  // Exit the application if MongoDB connection fails
  process.exit(1);
});

const usersSchema = new mongoose.Schema({
    name: {
        type: String,
    },
    email: {
        type: String,
        unique: true,
    },
    password: {
        type: String,
    },
    token: {
        type: String,
    },
});

const users = mongoose.model('Users', usersSchema);

// Use a randomly generated secure secret key for JWT
const jwtSecretKey = process.env.JWT_SECRET_KEY || 'your-secret-key';

// Signup route with validation
app.post('/signup', [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;

        // Check if email already exists
        const existingUser = await users.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new users({
            name,
            email,
            password: hashedPassword,
        });

        // Generate JWT token
        const token = jwt.sign({ userId: newUser._id }, jwtSecretKey);
        newUser.token = token;

        // Save the user to the database
        await newUser.save();

        res.status(201).json({ message: "User created successfully", token });
    } catch (error) {
        console.error("Error signing up user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Login route with validation
app.post('/login', [
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        // Find user by email
        const user = await users.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: "Incorrect password" });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, jwtSecretKey);
        user.token = token;
        await user.save();

        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        console.error("Error logging in:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Logout route
app.post('/logout', async (req, res) => {
    try {
        // Update user token to null
        const user = await users.findOneAndUpdate({ token: req.headers.authorization }, { token: null });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ message: "Logout successful" });
    } catch (error) {
        console.error("Error logging out:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Protected route
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    jwt.verify(token, jwtSecretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid token" });
        }
        req.userId = decoded.userId;
        next();
    });
};

app.get('/protected-route', verifyToken, (req, res) => {
    res.json({ message: "This route is protected" });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
