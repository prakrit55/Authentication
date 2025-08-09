import {Request, Response, NextFunction} from 'express';

/**
 * Middleware to verify if the authenticated user's role is allowed to access the route.
 *
 * @param allowedRoles - A list of roles permitted to access the route.
 * @returns Express middleware function that checks the user's role and either allows access or returns a 403 error.
 *
 * @example
 * app.get('/admin', authroleverify('admin'), (req, res) => { ... });
 */
export const authroleverify = (...allowedRoles: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: "Access Denied!"})
        }
        next();
    };
};