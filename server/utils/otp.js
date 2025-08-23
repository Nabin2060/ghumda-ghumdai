import Crypto from 'crypto';

export const generateOtp = () => {
    return Crypto.randomInt(100000, 999999);
};