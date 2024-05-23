const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const sendEmail = require('../utils/mailer');

const signup = async (req, res) => {
    const { username, email, password, nic } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        user = await User.findOne({ nic });
        if (user) {
            return res.status(400).json({ message: 'NIC already exists' });
        }

        user = new User({ username, email, password, nic });
        await user.save();

        sendEmail(email, 'Registration Successful', 'You have successfully registered.');

        res.status(201).json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

const login = async (req, res) => {
    const { nic, password } = req.body;
    try {
        const user = await User.findOne({ nic });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });

        res.status(200).json({ success: true, token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

const generateOtp = async (req, res) => {
    const { nic } = req.body;
    try {
        const user = await User.findOne({ nic });
        if (!user) {
            return res.status(400).json({ message: 'Invalid NIC' });
        }

        const otp = Math.floor(1000 + Math.random() * 9000);
        // Ideally, save the OTP in the database with an expiry time

        sendEmail(user.email, 'Your OTP Code', `Your OTP code is ${otp}`);

        const token = jwt.sign({ id: user._id, otp }, 'secret', { expiresIn: '5m' });

        res.status(200).json({ success: true, token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

const verifyOtp = async (req, res) => {
    const { token, otp } = req.body;
    try {
        const decoded = jwt.verify(token, 'secret');
        if (decoded.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        const authToken = jwt.sign({ id: decoded.id }, 'secret', { expiresIn: '1h' });

        res.status(200).json({ success: true, token: authToken });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};
