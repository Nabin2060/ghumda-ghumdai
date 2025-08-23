import userModel from '../models/user.model.js';
import { generateOtp } from '../utils/otp.js';
import { generateToken } from '../utils/token.js';

export const register = async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const user = await userModel.findOne({ email: email.toLowerCase() });
        if (user) {
            return res.status(400).json({
                success: false,
                message: "User already exists"
            });
        }
        // validate

        //hash password
        const hashedPassword = await hashPassword(password);
        // generate otp
        const otp = generateOtp();

        //create new user
        const newUser = new userModel({
            username,
            email: email.toLowerCase(),
            password: hashedPassword,
            role: "user",
            otp,
            isEmailVerified: false,
            isActive: true,
            loginAttempts: 0
        });
        await newUser.save();
        // generate token
        const token = generateToken(newUser._id, newUser.roles);

        // send email 

        // return success response 
        res.status(201).json({
            success: true,
            message: "User registered successfully",
            data: {
                token: token
            }
        });
    } catch (err) {
        console.log(`Error occurred during registration: ${err.message}`);
        res.status(500).json({
            success: false,
            message: 'Registration failed. Please try again later.'
        });
    }
}