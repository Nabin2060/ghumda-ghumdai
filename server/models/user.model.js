
import mongoose from "mongoose";
import bcryptjs from 'bcryptjs';

// User schema definition with best practices
const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            trim: true,
            minlength: 3,
            maxlength: 30,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
            match: [/.+@.+\..+/, "Please enter a valid email address"],
        },
        password: {
            type: String,
            required: true,
            minlength: 8,
            select: false, // Do not return password by default
        },
        role: {
            type: [String],
            enum: ["user", "traveler", "admin"],
            default: ["user"],
            required: true,
        },
        profilePicture: {
            type: String,
            default: null,
        },
        phoneNumber: {
            type: String,
            validate: {
                validator: function (v) {
                    return /^[0-9]{10}$/.test(v);
                },
                message: "Phone number must be 10 digits"
            }
        },
        address: {
            street: String,
            city: String,
            state: String,
            country: String,
        },
        isActive: {
            type: Boolean,
            default: true,
        },
        isEmailVerified: {
            type: Boolean,
            default: false,
        },
        lastLogin: {
            type: Date,
        },
        refreshTokens: [{
            token: String,
            createdAt: {
                type: Date,
                default: Date.now,
                expires: 604800 // 7 days in seconds
            }
        }],
        preferences: {
            language: {
                type: String,
                default: "en",
                enum: ["en", "ne", "hi"]
            },
            currency: {
                type: String,
                default: "NPR",
                enum: ["NPR", "USD"]
            },
            notifications: {
                email: { type: Boolean, default: true },
                sms: { type: Boolean, default: false },
                push: { type: Boolean, default: true }
            }
        },
        // Traveler-specific profile (only for traveler applications)
        travelerProfile: {
            businessName: String,
            businessLicense: String,
            approvalStatus: {
                type: String,
                enum: ["pending", "approved", "rejected"],
                default: "pending"
            },
            isApproved: {
                type: Boolean,
                default: false
            },
            appliedAt: Date,
            approvedAt: Date,
            rejectedAt: Date,
            approvedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User'
            },
            rejectedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User'
            },
            rejectionReason: String
        }
    },
    {
        timestamps: true, // Adds createdAt and updatedAt fields
        versionKey: false, // Removes __v field
    }
);

// Indexes for performance and uniqueness
userSchema.index({ email: 1 }, { unique: true });
// userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ isActive: 1 });
userSchema.index({ 'travelerProfile.approvalStatus': 1 });

// Virtual for user's full name (if needed later)
userSchema.virtual('fullName').get(function () {
    return `${this.firstName} ${this.lastName}`;
});

// Pre-save middleware removed - using hash.js functions in controller instead

// Instance method to compare passwords (using your hash.js function)
userSchema.methods.comparePassword = async function (candidatePassword) {
    const { comparePassword } = await import('../utils/hash.js');
    return await comparePassword(candidatePassword, this.password);
};

// Instance method to generate auth token - using your token.js function
userSchema.methods.generateAuthToken = function () {
    const { generateToken } = require('../utils/token.js');
    return generateToken(this._id);
};

// Static method to find active users
userSchema.statics.findActiveUsers = function () {
    return this.find({ isActive: true });
};

// Static method to find by email or username
userSchema.statics.findByEmailOrUsername = function (identifier) {
    return this.findOne({
        $or: [
            { email: identifier },
            { username: identifier }
        ]
    });
};

// Static method to find pending traveler applications
userSchema.statics.findPendingTravelers = function () {
    return this.find({ 'travelerProfile.approvalStatus': 'pending' });
};

const User = mongoose.model("User", userSchema);

export default User;