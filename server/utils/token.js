import jwt from 'jsonwebtoken';
import config from '../config/config.js';


export const generateToken = (payload) =>
    jwt.sign({
        data: payload,
    },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    );

export const verifyToken = (token) => jwt.verify(token, config.JWT_SECRET);

