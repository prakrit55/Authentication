import express from 'express';
import {signup, login}  from './authcontroller';
const router = express.Router();

router.post('/register', signup);
router.post('/signin', login);

export default router;
