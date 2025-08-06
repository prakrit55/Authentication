import { boolean } from 'joi';
import mongoose from 'mongoose';

const userschema = new mongoose.Schema({
    email:{
        type: String,
        required: true,
        unique: [true, "Email already exists"],
        minLength: 5,
        lowercase: true,
    },
    password: {
        type: String,
        required: true,
        minLength: 6,
        trim: true,
        select: false, // Do not return password in queries
    },
    verified:{
        type: Boolean,
        select: false,
    },
    verificationcode:{
        type: String,
        select: false,
    },
    verificationCodeValidation: {
			type: Number,
			select: false,
	},
    resetpassword: {
        type: String,
        select: false,
    },
    resetpasswordtoken: {
        type: String,
        select: false,
    },
},{
    timestamps: true,
    versionKey: false,
})

export default mongoose.model('User', userschema);