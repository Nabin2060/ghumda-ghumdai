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

// Admin function to approve/reject traveler applications
export const approveTraveler = async (req, res) => {
    const { userId, action } = req.body; // action: 'approve' or 'reject'

    try {
        // Check if current user is admin
        if (!req.user.role.includes('admin')) {
            return res.status(403).json({
                success: false,
                message: "Access denied. Admin privileges required."
            });
        }

        // Find the user
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // Check if user has pending traveler application
        if (!user.travelerProfile || user.travelerProfile.approvalStatus !== 'pending') {
            return res.status(400).json({
                success: false,
                message: "No pending traveler application found for this user"
            });
        }

        if (action === 'approve') {
            // Approve traveler
            user.role = ["traveler"];
            user.travelerProfile.approvalStatus = 'approved';
            user.travelerProfile.isApproved = true;
            user.travelerProfile.approvedAt = new Date();
            user.travelerProfile.approvedBy = req.user._id;

            await user.save();

            // Send approval email to user

            res.status(200).json({
                success: true,
                message: "Traveler application approved successfully",
                data: {
                    userId: user._id,
                    username: user.username,
                    newRole: user.role,
                    approvalStatus: 'approved'
                }
            });

        } else if (action === 'reject') {
            // Reject traveler
            user.travelerProfile.approvalStatus = 'rejected';
            user.travelerProfile.isApproved = false;
            user.travelerProfile.rejectedAt = new Date();
            user.travelerProfile.rejectedBy = req.user._id;

            await user.save();

            // Send rejection email to user

            res.status(200).json({
                success: true,
                message: "Traveler application rejected",
                data: {
                    userId: user._id,
                    username: user.username,
                    approvalStatus: 'rejected'
                }
            });

        } else {
            return res.status(400).json({
                success: false,
                message: "Invalid action. Use 'approve' or 'reject'"
            });
        }

    } catch (err) {
        console.log(`Error occurred during traveler approval: ${err.message}`);
        res.status(500).json({
            success: false,
            message: 'Approval process failed. Please try again later.'
        });
    }
}

// Get pending traveler applications (Admin only)
export const getPendingTravelers = async (req, res) => {
    try {
        // Check if current user is admin
        if (!req.user.role.includes('admin')) {
            return res.status(403).json({
                success: false,
                message: "Access denied. Admin privileges required."
            });
        }

        const pendingTravelers = await userModel.find({
            'travelerProfile.approvalStatus': 'pending'
        }).select('-password').sort({ 'travelerProfile.appliedAt': -1 });

        res.status(200).json({
            success: true,
            message: "Pending traveler applications fetched successfully",
            data: {
                count: pendingTravelers.length,
                travelers: pendingTravelers
            }
        });

    } catch (err) {
        console.log(`Error occurred while fetching pending travelers: ${err.message}`);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending applications.'
        });
    }
}

