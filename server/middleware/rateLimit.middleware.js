import rateLimit from 'express-rate-limit';

// General rate limiter
export const rateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Strict rate limiter for authentication routes
export const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts per windowMs
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again after 15 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // Don't count successful requests
});

// Password reset rate limiter
export const passwordResetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // Limit each IP to 5 password reset attempts per hour
    message: {
        success: false,
        message: 'Too many password reset attempts, please try again after 1 hour.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// OTP rate limiter
export const otpLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 6, // Limit each IP to 6 OTP requests per 10 minutes
    message: {
        success: false,
        message: 'Too many OTP requests, please try again after 10 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Registration rate limiter
export const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 7, // Limit each IP to 7 registration attempts per hour
    message: {
        success: false,
        message: 'Too many registration attempts, please try again after 1 hour.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
