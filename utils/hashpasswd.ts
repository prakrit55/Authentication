import bcrypt from 'bcrypt';
import crypto from 'crypto';

export const hashPassword = async (password: string) => {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword;
    } catch (error) {
        throw new Error('Error hashing password');
    }
};

export const comparePassword = async (password: string, hashedPassword: string) => {
    try {
        const isMatch = await bcrypt.compare(password, hashedPassword);
        return isMatch;
    } catch (error) {
        throw new Error('Error comparing password');
    }
}

export const hmacCode = async (data: string, secret: string) => {
    const result = crypto.createHmac('sha256', secret).update(data).digest('hex');
    return result;
}