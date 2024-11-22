require("dotenv").config()

const { dynamoDB } = require('../../config/awsConfig');
const { UpdateItemCommand } = require('@aws-sdk/client-dynamodb');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { sendEmailOTP } = require('../../utils/sendEmailOTP');
const { sendSmsOTP } = require('../../utils/sendSmsOTP');
const User = require('./authModel');

// Signup with OTP
exports.signup = async (req, res) => {
    try {
        const { email, phone } = req.body;
        if (!email && !phone) return res.status(400).json({ message: 'Email or phone is required' });

        const existingUser = await User.findUserByEmailOrPhone(email, phone);
        if (existingUser) return res.status(400).json({ message: 'User already exists' });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

        await User.createUser({ email, phone, otp, otpExpiry });
        console.log(`Generated OTP for ${email || phone}: ${otp}`);

        if (email) await sendEmailOTP(email, otp);
        if (phone) await sendSmsOTP(phone, otp);

        res.status(200).json({ message: 'OTP sent' });
    } catch (error) {
        console.error('Error in signup:', error);
        res.status(500).json({ message: 'Server error',error:error.message });
    }
};

// Verify OTP
exports.verifyOTP = async (req, res) => {
    try {
        const { email, phone, otp } = req.body;

        console.log("Request body:", req.body);

        const user = await User.findUserByEmailOrPhone(email, phone);
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        const storedOtp = user.otp.S;
        const otpExpiry = user.otpExpiry.S;

        console.log(`Stored OTP: ${storedOtp}, Provided OTP: ${otp}`);
        console.log(`OTP Expiry Time: ${otpExpiry} (Database), Current Time: ${new Date().toISOString()} (UTC)`);

        if (storedOtp !== otp) {
            return res.status(400).json({ message: 'Incorrect OTP' });
        }

        if (new Date(otpExpiry) < Date.now()) {
            return res.status(400).json({ message: 'Expired OTP' });
        }

        const token = jwt.sign({ email: user.email.S, phone: user.phone.S }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const updateParams = {
            TableName: process.env.DYNAMODB_TABLE_NAME,
            Key: {
                usersPartitionkey: { S: user.usersPartitionkey.S },
                usersSortKey: { S: 'user' },
            },
            UpdateExpression: 'REMOVE otp, otpExpiry',
        };

        await dynamoDB.send(new UpdateItemCommand(updateParams));

        res.status(200).json({ message: 'OTP verified', token });
    } catch (error) {
        console.error('Error in verifyOTP:', error);
        res.status(500).json({ message: 'Server error',error:error.message });
    }
};

// Create Password
exports.createPassword = async (req, res) => {
    try {
        const { token, password } = req.body;

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const identifier = decoded.email || decoded.phone;

        if (!identifier) {
            return res.status(400).json({ message: 'Invalid token data' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        console.log('Identifier:', identifier);
        console.log('Update Expression:', 'SET password = :password');
        console.log('Expression Attribute Values:', { ':password': { S: hashedPassword } });

        await User.updateUser(identifier, 'SET password = :password', { ':password': { S: hashedPassword } });

        res.status(200).json({ message: 'Password created successfully' });
    } catch (error) {
        console.error('Error in createPassword:', error);
        res.status(500).json({ message: 'Server error' ,error:error.message});
    }
};

// Login
exports.login = async (req, res) => {
    try {
        console.log("login hit");

        const { email, phone, password } = req.body;
        const user = await User.findUserByEmailOrPhone(email, phone);

        if (!user || !(await bcrypt.compare(password, user.password.S))) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ email: user.email.S, phone: user.phone.S }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Error in login:', error);
        res.status(500).json({ message: 'Server error',error:error.message });
    }
};
