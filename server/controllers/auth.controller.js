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

// User Login (role: user only)
export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('User login attempt:', { email: email.toLowerCase() });

        // Find user with user role
        const user = await userModel.findOne({
            email: email.toLowerCase(),
            role: { $in: ["user"] }
        }).select('+password');

        console.log('User found:', user ? 'YES' : 'NO');

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid email or password or account type",
            });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message: "User account is not active. Please contact support."
            });
        }

        // Check if user is blocked
        if (user.isBlocked) {
            if (user.blockExpiry && new Date() > user.blockExpiry) {
                // Auto-unblock the user
                user.isBlocked = false;
                user.blockedAt = null;
                user.blockedBy = null;
                user.blockReason = "";
                user.blockExpiry = null;
                await user.save();
            } else {
                return res.status(403).json({
                    success: false,
                    message: 'Account is blocked',
                    data: {
                        reason: user.blockReason,
                        blockedAt: user.blockedAt,
                        blockExpiry: user.blockExpiry
                    }
                });
            }
        }

        // Verify password
        const isPasswordValid = await comparePassword(password, user.password);
        console.log('Password valid:', isPasswordValid);

        if (!isPasswordValid) {
            user.loginAttempts += 1;
            await user.save();
            return res.status(401).json({
                success: false,
                message: "Invalid email or password",
            });
        }

        // Reset login attempts and update last login
        user.loginAttempts = 0;
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token using your token.js function
        const token = generateToken(user._id);

        res.status(200).json({
            success: true,
            message: 'User login successful',
            data: {
                user: sanitizeUser(user),
                token: token,
                userType: 'user'
            }
        });

    } catch (err) {
        console.log(`Error occurred during user login: ${err.message}`);
        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again later.'
        });
    }
};

// Traveler Login (role: traveler, approved only)
export const loginTraveler = async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('Traveler login attempt:', { email: email.toLowerCase() });

        // Find traveler with traveler role and approved status
        const traveler = await userModel.findOne({
            email: email.toLowerCase(),
            role: { $in: ["traveler"] },
            'travelerProfile.isApproved': true,
            'travelerProfile.approvalStatus': 'approved'
        }).select('+password');

        console.log('Traveler found:', traveler ? 'YES' : 'NO');

        if (!traveler) {
            return res.status(400).json({
                success: false,
                message: "Invalid credentials or account not approved for traveler access",
            });
        }

        // Check if traveler is active
        if (!traveler.isActive) {
            return res.status(403).json({
                success: false,
                message: "Traveler account is not active. Please contact support."
            });
        }

        // Check if traveler is blocked
        if (traveler.isBlocked) {
            if (traveler.blockExpiry && new Date() > traveler.blockExpiry) {
                // Auto-unblock
                traveler.isBlocked = false;
                traveler.blockedAt = null;
                traveler.blockedBy = null;
                traveler.blockReason = "";
                traveler.blockExpiry = null;
                await traveler.save();
            } else {
                return res.status(403).json({
                    success: false,
                    message: 'Traveler account is blocked',
                    data: {
                        reason: traveler.blockReason,
                        blockedAt: traveler.blockedAt,
                        blockExpiry: traveler.blockExpiry
                    }
                });
            }
        }

        // Verify password
        const isPasswordValid = await comparePassword(password, traveler.password);
        console.log('Password valid:', isPasswordValid);

        if (!isPasswordValid) {
            traveler.loginAttempts += 1;
            await traveler.save();
            return res.status(401).json({
                success: false,
                message: "Invalid email or password",
            });
        }

        // Reset login attempts and update last login
        traveler.loginAttempts = 0;
        traveler.lastLogin = new Date();
        await traveler.save();

        // Generate JWT token using your token.js function
        const token = generateToken(traveler._id);

        res.status(200).json({
            success: true,
            message: 'Traveler login successful',
            data: {
                user: sanitizeUser(traveler),
                token: token,
                userType: 'traveler',
                businessInfo: {
                    businessName: traveler.travelerProfile.businessName,
                    approvedAt: traveler.travelerProfile.approvedAt
                }
            }
        });

    } catch (err) {
        console.log(`Error occurred during traveler login: ${err.message}`);
        res.status(500).json({
            success: false,
            message: 'Login failed. Please try again later.'
        });
    }
};

// Admin Login (role: admin only)
export const loginAdmin = async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log('Admin login attempt:', { email: email.toLowerCase() });

        // Find admin with admin role
        const admin = await userModel.findOne({
            email: email.toLowerCase(),
            role: { $in: ["admin"] }
        }).select('+password');

        console.log('Admin found:', admin ? 'YES' : 'NO');

        if (!admin) {
            return res.status(400).json({
                success: false,
                message: "Invalid admin credentials",
            });
        }

        // Check if admin is active
        if (!admin.isActive) {
            return res.status(403).json({
                success: false,
                message: "Admin account is not active. Please contact super admin."
            });
        }

        // Admins cannot be blocked by other admins (security measure)

        // Verify password
        const isPasswordValid = await comparePassword(password, admin.password);
        console.log('Password valid:', isPasswordValid);

        if (!isPasswordValid) {
            admin.loginAttempts += 1;
            await admin.save();
            return res.status(401).json({
                success: false,
                message: "Invalid admin credentials",
            });
        }

        // Reset login attempts and update last login
        admin.loginAttempts = 0;
        admin.lastLogin = new Date();
        await admin.save();

        // Generate JWT token with longer expiry for admin using your token.js function
        const token = generateToken(admin._id);

        res.status(200).json({
            success: true,
            message: 'Admin login successful',
            data: {
                user: sanitizeUser(admin),
                token: token,
                userType: 'admin',
                permissions: ['manage_users', 'approve_travelers', 'system_admin']
            }
        });

    } catch (err) {
        console.log(`Error occurred during admin login: ${err.message}`);
        res.status(500).json({
            success: false,
            message: 'Admin login failed. Please try again later.'
        });
    }
};

export const logout = async (req, res) => {
    try {
        // In a more advanced implementation, you might want to blacklist the token
        // For now, we'll just return a success response
        res.status(200).json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            message: 'Logout failed'
        });
    }
};

// Verify Email OTP
export const verifyEmail = async (req, res) => {
    try {
        const { email, otp } = req.body;

        const user = await userModel.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.isEmailVerified) {
            return res.status(400).json({
                success: false,
                message: 'Email is already verified'
            });
        }

        if (user.otp !== otp) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        // Verify email
        user.isEmailVerified = true;
        user.otp = '';
        await user.save();

        res.status(200).json({
            success: true,
            message: 'Email verified successfully'
        });

    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Email verification failed'
        });
    }
};

// Resend OTP
export const resendOTP = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await userModel.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.isEmailVerified) {
            return res.status(400).json({
                success: false,
                message: 'Email is already verified'
            });
        }

        // Generate new OTP
        const newOTP = generateOTP();
        user.otp = newOTP;
        await user.save();

        // TODO: Send new OTP email
        // await sendOTPEmail(email, newOTP);

        res.status(200).json({
            success: true,
            message: 'OTP sent successfully'
        });

    } catch (error) {
        console.error('Resend OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to resend OTP'
        });
    }
};

