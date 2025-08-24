import userModel from '../models/user.model.js';
import { generateOtp } from '../utils/otp.js';
import { generateToken, verifyToken } from '../utils/token.js';
import { hashPassword, comparePassword } from '../utils/hash.js';

// Helper function to sanitize user data (remove sensitive info)
const sanitizeUser = (user) => {
    const { password, otp, refreshTokens, ...sanitizedUser } = user.toObject();
    return sanitizedUser;
};

// Regular User Registration
export const register = async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if user already exists - email check only
        const existingUser = await userModel.findOne({ email: email.toLowerCase() });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User with this email already exists"
            });
        }

        // Validate input (add more validation as needed)
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters long"
            });
        }

        // Hash password using your hash.js function
        const hashedPassword = await hashPassword(password);
        // Generate OTP
        const otp = generateOtp();

        // Create new user with default 'user' role
        const newUser = new userModel({
            username,
            email: email.toLowerCase(),
            password: hashedPassword, // Using your hash function
            role: ["user"], // Default role for regular users
            otp,
            isEmailVerified: false,
            isActive: true,
            loginAttempts: 0
        });

        await newUser.save();

        // Generate token using your token.js function
        const token = generateToken(newUser._id);

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

// Traveler Registration (Pending Admin Approval)
export const registerTraveler = async (req, res) => {
    const { username, email, password, businessName, businessLicense, phoneNumber, address } = req.body;

    try {
        // Check if user already exists - email check only
        const existingUser = await userModel.findOne({ email: email.toLowerCase() });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User with this email already exists"
            });
        }

        // Validate required fields for traveler
        if (!username || !email || !password || !businessName || !phoneNumber) {
            return res.status(400).json({
                success: false,
                message: "All required fields must be provided"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters long"
            });
        }

        // Hash password using your hash.js function
        const hashedPassword = await hashPassword(password);
        // Generate OTP
        const otp = generateOtp();

        // Create new traveler with 'user' role initially (pending approval)
        const newTraveler = new userModel({
            username,
            email: email.toLowerCase(),
            password: hashedPassword, // Using your hash function
            role: ["user"], // Initially user role, will be changed to traveler after admin approval
            phoneNumber,
            address,
            otp,
            isEmailVerified: false,
            isActive: true,
            loginAttempts: 0,
            // Add traveler-specific fields
            travelerProfile: {
                businessName,
                businessLicense,
                approvalStatus: "pending", // pending, approved, rejected
                appliedAt: new Date(),
                isApproved: false
            }
        });

        await newTraveler.save();

        // Generate token using your token.js function
        const token = generateToken(newTraveler._id);

        // Send email notification to admin about new traveler application

        // Return success response 
        res.status(201).json({
            success: true,
            message: "Traveler application submitted successfully. Waiting for admin approval.",
            data: {
                token: token,
                approvalStatus: "pending"
            }
        });
    } catch (err) {
        console.log(`Error occurred during traveler registration: ${err.message}`);
        res.status(500).json({
            success: false,
            message: 'Traveler registration failed. Please try again later.'
        });
    }
}

