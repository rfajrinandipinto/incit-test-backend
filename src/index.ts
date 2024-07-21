import express from 'express';
import session from 'express-session';
import cors from 'cors';
import passport from 'passport';
import { PrismaClient } from '@prisma/client';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth';
import './middleware/passport';
import jwt from 'jsonwebtoken';

const app = express();
const prisma = new PrismaClient();
const port = process.env.PORT || 5000;

app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:3000', // Replace with your frontend URL
    credentials: true, // Allow cookies to be sent
}));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
        httpOnly: false,
        secure: true,
        sameSite: 'none', // 'none' for production with HTTPS
    },
}));

app.use(passport.initialize());
app.use(passport.session());

app.use('/api/auth', authRoutes(prisma));


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
