import joi from 'joi';

export const validateSchema = joi.object({
    email: joi.string().
    min(6).
    max(60).
    email({
        tlds: { allow: ['com', 'net', 'org'] }
    }),
    password: joi.string().
    required().
    pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
})

export const signinSchema = joi.object({
    email: joi.string().
    min(6).
    max(60).
    email({
        tlds: { allow: ['com', 'net', 'org'] }
    }),
    password: joi.string().
    required().
    pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
})

export const validatecodeemail = joi.object({
    email : joi.string().
    min(6).
    max(60).
    required().
    email({
        tlds: { allow: ['com', 'net', 'org'] }
    }),
    code: joi.number().required(),
});

export const validatechangepassword = joi.object({
    oldPassword: joi.string().
    required().
    pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
    newPassword: joi.string().
    required().
    pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
})

export const acceptRPSchema = joi.object({
    email: joi.string().
    min(6).
    max(60).
    required().
    email({
        tlds: { allow: ['com', 'net', 'org'] }
    }),
    code: joi.number().required(),
    newPassword: joi.string().
    required().
    pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
})