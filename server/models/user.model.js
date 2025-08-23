
import mongoose from "mongoose";

// User schema definition with best practices
const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
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
        }
    },
    {
        timestamps: true, // Adds createdAt and updatedAt fields
        versionKey: false, // Removes __v field
    }
);

// Indexes for performance and uniqueness
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 });
userSchema.index({ isActive: 1 });

// Virtual for user's full name (if needed later)
userSchema.virtual('fullName').get(function () {
    return `${this.firstName} ${this.lastName}`;
});


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

// Optionally, add pre-save hooks, methods, or statics here

const User = mongoose.model("User", userSchema);

export default User;