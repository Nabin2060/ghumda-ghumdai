import { body, validationResult } from 'express-validator';

// Validation error handler
export const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: errors.array()
        });
    }

    next();
};

// Registration validation
export const validateRegister = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be between 3 and 30 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username can only contain letters, numbers, and underscores'),

    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),

    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),

    handleValidationErrors
];

// Traveler registration validation
export const validateTravelerRegister = [
    ...validateRegister.slice(0, -1), // All register validations except error handler

    body('businessName')
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Business name must be between 2 and 100 characters'),

    body('phoneNumber')
        .matches(/^[0-9]{10}$/)
        .withMessage('Phone number must be exactly 10 digits'),

    body('businessLicense')
        .optional()
        .trim()
        .isLength({ min: 5, max: 50 })
        .withMessage('Business license must be between 5 and 50 characters'),

    handleValidationErrors
];

// Login validation
export const validateLogin = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),

    body('password')
        .notEmpty()
        .withMessage('Password is required'),

    handleValidationErrors
];

// Email verification validation
export const validateEmailVerification = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),

    body('otp')
        .isLength({ min: 4, max: 6 })
        .isNumeric()
        .withMessage('OTP must be 4-6 digits'),

    handleValidationErrors
];

// Password reset validation
export const validatePasswordReset = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),

    body('otp')
        .isLength({ min: 4, max: 6 })
        .isNumeric()
        .withMessage('OTP must be 4-6 digits'),

    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),

    handleValidationErrors
];

// Traveler approval validation
export const validateTravelerApproval = [
    body('userId')
        .isMongoId()
        .withMessage('Valid user ID is required'),

    body('action')
        .isIn(['approve', 'reject'])
        .withMessage('Action must be either approve or reject'),

    body('rejectionReason')
        .if(body('action').equals('reject'))
        .notEmpty()
        .withMessage('Rejection reason is required when rejecting'),

    handleValidationErrors
];
