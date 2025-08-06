import express from 'express';
import type { Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import authrouter from '../routers/authrouter';

const app = express();


app.use(cookieParser());
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));


app.use('/api/auth', authrouter);

const mongo = mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/mydatabase').then(() => {
    console.log('Connected to MongoDB');
})

app.get('/', (req:Request,res:Response)=>{
    res.send('Hello World!');
})

app.listen(process.env.PORT || 3000, () => {
    console.log('Server is running on port 3000');
})

// module.exports = mongo;