// Role-based authorization middleware
export const authorize = (allowedRoles = []) => {
    return (req, res, next) => {
        try {
            // Check if user is authenticated
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required.'
                });
            }

            // Check if user has required role
            const userRoles = req.user.role || [];
            const hasPermission = allowedRoles.some(role => userRoles.includes(role));

            if (!hasPermission) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required roles: ${allowedRoles.join(', ')}`
                });
            }

            next();

        } catch (error) {
            console.error('Authorization error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization failed.'
            });
        }
    };
};

// Check if user is admin
export const isAdmin = (req, res, next) => {
    return authorize(['admin'])(req, res, next);
};

// Check if user is traveler or admin
export const isTravelerOrAdmin = (req, res, next) => {
    return authorize(['traveler', 'admin'])(req, res, next);
};

// Check if user owns the resource or is admin
export const isOwnerOrAdmin = (resourceUserIdField = 'userId') => {
    return (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required.'
                });
            }

            // Admin can access everything
            if (req.user.role.includes('admin')) {
                return next();
            }

            // Check if user owns the resource
            const resourceUserId = req.params[resourceUserIdField] || req.body[resourceUserIdField];

            if (req.user._id.toString() === resourceUserId) {
                return next();
            }

            return res.status(403).json({
                success: false,
                message: 'Access denied. You can only access your own resources.'
            });

        } catch (error) {
            console.error('Ownership authorization error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization failed.'
            });
        }
    };
};

// Check if user is approved traveler
export const isApprovedTraveler = (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required.'
            });
        }

        // Check if user has traveler role and is approved
        if (!req.user.role.includes('traveler')) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Traveler role required.'
            });
        }

        if (!req.user.travelerProfile ||
            !req.user.travelerProfile.isApproved ||
            req.user.travelerProfile.approvalStatus !== 'approved') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Traveler account not approved.'
            });
        }

        next();

    } catch (error) {
        console.error('Traveler authorization error:', error);
        return res.status(500).json({
            success: false,
            message: 'Authorization failed.'
        });
    }
};

// Check user role type
export const checkUserType = (allowedTypes = []) => {
    return (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required.'
                });
            }

            const userType = req.user.role[0]; // Get primary role

            if (!allowedTypes.includes(userType)) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Allowed user types: ${allowedTypes.join(', ')}`
                });
            }

            next();

        } catch (error) {
            console.error('User type check error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization failed.'
            });
        }
    };
};