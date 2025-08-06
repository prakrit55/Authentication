import User from '../models/usermodels';
import {validateSchema, signinSchema, validatecodeemail} from '../middlewares/validator';
import {hashPassword, comparePassword, hmacCode} from '../utils/hashpasswd';
import type { Request, Response } from 'express';
import transporter from 'nodemailer'
import jwt from 'jsonwebtoken';


/**
 * Handles user signup by validating input, checking for existing users,
 * hashing the password, and saving the new user to the database.
 *
 * @param req - Express request object containing the user's email and password in the body.
 * @param res - Express response object used to send the response.
 * @returns A JSON response indicating success or failure of the signup process.
 *
 * @remarks
 * - Returns 401 if validation fails or if the user already exists.
 * - Returns 201 and the created user (without password) if successful.
 * - On error, logs the error to the console.
 */
export const signup = async (req:Request , res:Response) => {
    const { email, password } = req.body;
    try {
        const {error} = validateSchema.validate({email, password});
        if (error){
            return res.status(401).json({success: false, error: error.details?.[0]?.message || 'Validation error'});
        }

        // Check if the user already exists
        const existinguser = await User.findOne({email})
        if (existinguser) {
            return res.status(401).json({success: false, error: "User already exists"});
        }

        // Hash the password
        // Create a new user instance
        const hashed = await hashPassword(password);
        const newUser = new User({
            email,
            password: hashed
        });

        // Save the new user to the database
        // Exclude the password from the response
        const savedUser = await newUser.save();
        const { password:  _password, ...userresponse } = savedUser.toObject();
        res.status(201).json({ success: true, message: "account has been created successfully", user: userresponse });
    }catch (err) {
        console.error(err);
    }
}

/**
 * Handles user login by validating credentials, checking user existence,
 * verifying password, and issuing a JWT token upon successful authentication.
 * 
 * @param req - Express request object containing `email` and `password` in the body.
 * @param res - Express response object used to send the authentication result.
 * 
 * @returns Sends a JSON response with success status, JWT token, and message on success,
 * or an error message on failure.
 * 
 * @throws Logs any unexpected errors to the console.
 */
export const login = async (req: Request, res: Response) => {
    const {email, password} = req.body;
    try {
        const {error, value} = signinSchema.validate({email, password});
        if (error) {
            return res.
            status(401).
            json({success: false, error: error.details?.[0]?.message || 'Validation error'});
        }
        const existingUser = await User.findOne({email}).select('+password');
            if (!existingUser) {
                return res.
                status(401).
                json({success: false, error: "User does not exist"});
            }
        const isMatch = await comparePassword(password, existingUser.password);
        if (!isMatch) {
            return res.
            status(401).
            json({success: false, error: "Invalid credentials"});
        }
        const token = jwt.sign(
            {
                userId: existingUser._id,
                email: existingUser.email,
                verified: existingUser.verified,
            },
            process.env.JWT_SECRET as string,
            {
                expiresIn: '8h', //
            }
        );
        res.cookie('Authorization', 'Bearer ' + token, {
            expires: new Date(Date.now() + 8 * 3600000), 
            httpOnly: process.env.NODE_ENV === 'production',
        }).
        json({
            success: true,
            token,
            message: "Login successful",
        });
    } catch (error) {
        console.log(error);
    }
}

export const logout = async (req: Request, res: Response) => {
    res.
    clearCookie('Authorization').
    status(200).
    json({success: true, message: "Logout successful"});
}



/**
 * Handles the process of sending a verification code to a user's email address.
 *
 * This controller function performs the following steps:
 * 1. Extracts the email from the request body.
 * 2. Searches for a user with the provided email in the database.
 * 3. Returns a 404 error if the user is not found.
 * 4. Returns a 400 error if the user is already verified.
 * 5. Generates a 6-digit verification code.
 * 6. Sends the verification code to the user's email using a configured transporter.
 * 7. If the email is sent successfully, hashes the code and stores it along with a validation timestamp in the user's document.
 * 8. Returns a success response if the code is sent, or an error response if sending fails.
 *
 * @param req - Express request object containing the user's email in the body.
 * @param res - Express response object used to send the HTTP response.
 * @returns A JSON response indicating success or failure of sending the verification code.
 */
export const getverificationcode = async (req: Request, res: Response) => {
    // Search the database for a user document whose "email" field matches the provided email.
    // `await` ensures we wait for the database query to complete before proceeding.

    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user){
            return res.
            status(404).
            json({success: false, error: "User not found"});
        }
        if (user.verified) {
            return res.
            status(400).
            json({success: false, error: "User already verified"});
        }

        const codevalue = Math.floor(100000 + Math.random() * 900000).toString();
        let ts = await transporter.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Verification Code',
            text: `Your verification code is ${codevalue}. It is valid for 10 minutes.`
        };

        const info = await ts.sendMail(mailOptions);

        if (info.accepted[0] === user.email) {
            const hashedCode = await hmacCode(
                codevalue,
                process.env.HMAC_SECRET as string
            );
    
            user.verificationcode = hashedCode;
            user.verificationCodeValidation = Date.now();
            await user.save();
            return res.status(200).json({
                success: true,
                message: "Verification code sent successfully"
            });
        }
        return res.status(500).json({
            success: false,
            error: "Failed to send verification code"
        });
    }catch (error) {
		console.log(error);
	}
}

/**
 * Verifies a user's email using a verification code.
 *
 * @param req - Express request object containing `email` and `code` in the body.
 * @param res - Express response object used to send the verification result.
 * @returns Sends a JSON response indicating success or failure of verification.
 *
 * @remarks
 * - Validates the input using `validatecodeemail`.
 * - Checks if the user exists and is not already verified.
 * - Ensures the verification code is present and not expired (5 minutes).
 * - Compares the provided code (after HMAC hashing) with the stored code.
 * - On success, marks the user as verified and clears verification fields.
 * - Handles and responds to various error scenarios.
 */
export const verifycode = async (req: Request, res: Response)=>{
    const {email, code} = req.body;
    try {
        const {error, value} = validatecodeemail.validate({email, code});
    
        if (error){
            return res.status(401).json({success: false, error: error.details?.[0]?.message || 'Validation error'});
        }
        const user = await User.findOne({ email: email}).select('+verificationcode +verificationCodeValidation');
        if (!user) {
            return res.status(404).json({success: false, error: "User not found"});
        }
        if (user.verified) {
            return res.status(400).json({success: false, error: "User already verified"});
        }
        if (!user.verificationcode || !user.verificationCodeValidation) {
            return res.status(400).json({success: false, error: "Verification code not sent or expired"});
        }
        if (Date.now() - user.verificationCodeValidation > 5 * 60 * 1000) {
            return res.status(400).json({success: false, error: "Verification code expired"});
        }
    
        const codefromfounduser = await hmacCode(
            code.toString(),
            process.env.HMAC_SECRET as string
        );
        
        if (codefromfounduser === user.verificationcode){
            user.verified = true;
            user.verificationcode = null;
            user.verificationCodeValidation = null;
            await user.save();
            return res.status(200).json({success: true, message: "User verified successfully"});
        }
        return res.status(400).json({success: false, error: "Invalid verification code"});
    }catch (error) {
        console.log(error);
    }  
};

