const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const registerUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        res.status(400);
        throw new Error("All fields are mandatory!");
    }
    const userAvailable = await User.findOne({ email });
    if (userAvailable) {
        res.status(400);
        throw new Error("User with this email already exists!");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
        username,
        email,
        password: hashedPassword,
    });
    if (user) {
        res.status(201).json({
            id: user.id,
            username: user.username,
            email: user.email,
        });
    } else {
        res.status(400);
        throw new Error("Invalid user data");
    }
    console.log("User created:", user);
    res.json({ message: "Register the user" });
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Email ve password alanları boş ise hata mesajı gönderir
    if (!email || !password) {
        res.status(400);
        throw new Error("All fields are mandatory!");
    }

    // Kullanıcıyı email adresine göre bulur
    const user = await User.findOne({ email });

    // Kullanıcı var ve şifre doğruysa, kullanıcıya bir JWT token gönderir
    if (user && (await bcrypt.compare(password, user.password))) {
        const token = jwt.sign(
            {
                user: {
                    username: user.username,
                    email: user.email,
                    id: user.id
                },
            },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
        );

        res.status(200).json({
            id: user.id,
            username: user.username,
            email: user.email,
            token,
        });
    } else {
        res.status(401);
        throw new Error("Invalid email or password");
    }
});


const currentUser = asyncHandler(async (req, res) => {
    res.json(req.user);
});

module.exports = { registerUser, loginUser, currentUser };