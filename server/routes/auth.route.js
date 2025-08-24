import express from 'express';
import {
    register,
    registerTraveler,
    loginUser,
    loginTraveler,
    loginAdmin,
    logout,
    verifyEmail,
    resendOTP,
    forgotPassword,
    resetPassword,
    refreshToken,
    approveTraveler,
    getPendingTravelers
} from '../controllers/auth.controller.js';
import { authenticate } from '../middleware/auth.middleware.js';
import { authorize } from '../middleware/role.middleware.js';
import { validateRegister, validateLogin } from '../middleware/validation.middleware.js';
import { rateLimiter, authRateLimiter, passwordResetLimiter, otpLimiter, registrationLimiter } from '../middleware/rateLimit.middleware.js';

const router = express.Router();

// Public routes (no authentication required)
router.post('/register', validateRegister, registrationLimiter, register);
router.post('/register-traveler', validateRegister, registrationLimiter, registerTraveler);

// Separate login endpoints with different rate limits
router.post('/login-user', validateLogin, authRateLimiter, loginUser);
router.post('/login-traveler', validateLogin, authRateLimiter, loginTraveler);
router.post('/login-admin', validateLogin, authRateLimiter, loginAdmin);

router.post('/verify-email', otpLimiter, verifyEmail);
router.post('/resend-otp', otpLimiter, resendOTP);
router.post('/forgot-password', passwordResetLimiter, forgotPassword);
router.post('/reset-password', resetPassword);

// Protected routes (authentication required)
router.post('/logout', authenticate, logout);
router.post('/refresh-token', authenticate, refreshToken);

// Admin only routes
router.get('/pending-travelers', authenticate, authorize(['admin']), getPendingTravelers);
router.post('/approve-traveler', authenticate, authorize(['admin']), approveTraveler);

export default router;