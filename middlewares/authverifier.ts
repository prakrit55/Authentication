import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

/**
 * Middleware to verify JWT token from the request.
 *
 * Checks for the token in the `Authorization` header (Bearer scheme) or in cookies.
 * If a valid token is found, it verifies the token using the secret key and attaches
 * the decoded payload to `req.user`. If no token is found or verification fails,
 * responds with a 401 Unauthorized error.
 *
 * @param req - Express request object
 * @param res - Express response object
 * @param next - Express next middleware function
 *
 * @returns Responds with 401 status if token is missing or invalid, otherwise calls `next()`.
 */
export const verifytoken = (req: Request, res: Response, next:NextFunction) =>{
    let token;
    let authHeader = req.headers.authorization || req.headers.Authorization;
    if (typeof authHeader === "string" && authHeader.startsWith("Bearer")) {
        token = authHeader.split(" ")[1];
    } else if (req.cookies.token) {
        token = req.cookies.token;
    }
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
}