import bcrypt from 'bcryptjs';
import config from '../config/config.js';

export const hashPassword = async (password) => {
    try {
        const saltRound = config.SALT_ROUNDS;
        const hashedPassword = await bcrypt.hash(password, saltRound);
        return hashedPassword;

    } catch (err) {
        console.log(`Error occurred during password hashing: ${err.message}`);
        throw new Error('Internal server error');
    };
};

// password comparison
export const comparePassword = async (password, hashedPassword) => {
    try {
        return await bcrypt.compare(password, hashedPassword);
    } catch (err) {
        throw new Error('Internal server error');
    }
}
