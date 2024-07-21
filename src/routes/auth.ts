import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
import { PrismaClient } from '@prisma/client';

export default function (prisma: PrismaClient) {
    const router = Router();

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    // Sign-Up Route
    router.post('/signup', async (req, res) => {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = uuidv4();


        // Generate a random 4 digit number for the user name
        const randomNumber = Math.floor(1000 + Math.random() * 9000);
        const userName = `User#${randomNumber}`;


        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                verificationToken,
                name: userName, // Add the generated userName here
            },
        });

        const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Email Verification',
            text: `Please verify your email by clicking the following link: ${verificationLink}`,
        });

        res.status(201).json({ message: 'User created. Please verify your email.', user });
    });

    // Email Verification Route
    router.get('/verify-email', async (req, res) => {
        let { token } = req.query;

        if (!token || typeof token !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid token' });
        }

        const user = await prisma.user.findFirst({ where: { verificationToken: token } });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid token' });
        }

        await prisma.user.update({
            where: { id: user.id },
            data: { verified: true, verificationToken: null, loginCount: user.loginCount! + 1 },
        });

        token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '1h' });

        res.cookie("token", token, {
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
            httpOnly: false,
            sameSite: "none",
            secure: true,
        });

        await prisma.session.create({
            data: {
                userId: user.id,
            },
        });


        res.json({ success: true, message: 'Email verified successfully' });
    });

    // Sign-In Route
    router.post('/signin', async (req, res) => {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        if (!user.verified) {
            return res.status(401).json({ message: 'Please verify your email before signing in.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Update login count
        const updatedUser = await prisma.user.update({
            where: { id: user.id },
            data: { loginCount: user.loginCount! + 1 },
        });



        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '1h' });

        res.cookie("token", token, {
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
            httpOnly: false,
            sameSite: "none",
            secure: true,
        });

        // res.cookie('token', token, { httpOnly: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000, secure: true }); // 1 day
        // Create a new session
        await prisma.session.create({
            data: {
                userId: user.id,
            },
        });

        res.json({ success: true });
    });


    // Sign-Out Route
    router.post('/signout', async (req, res) => {
        try {
            // Assuming you have a way to extract userId from the request
            const authHeader = req.headers.authorization;
            if (authHeader) {
                const token = authHeader.split(' ')[1];
                const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
                const userId = decoded.userId;

                // Clear session
                await prisma.session.deleteMany({ where: { userId } });

                // Update logout timestamp
                await prisma.user.update({
                    where: { id: userId },
                    data: { logoutTimestamp: new Date() },
                });
            }

            res.clearCookie('token');
            res.json({ success: true, message: 'Logged out successfully' });
        } catch (err) {
            console.error('Error during logout:', err);
            res.status(500).json({ success: false, message: 'Logout failed' });
        }
    });

    // Fetch User Profile Information
    router.get('/profile', async (req, res) => {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!);
            const userId = (decoded as any).userId;

            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: { email: true, name: true },
            });

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            res.json({ user });
        } catch (error) {
            res.status(401).json({ message: 'Invalid token' });
        }
    });

    // Update User Profile
    router.put('/update-profile', async (req, res) => {
        const authHeader = req.headers.authorization;
        const { name } = req.body;

        if (!authHeader) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!);
            const userId = (decoded as any).userId;

            if (!name) {
                return res.status(400).json({ message: 'Name is required' });
            }

            const user = await prisma.user.update({
                where: { id: userId },
                data: { name },
            });

            res.json({ user });
        } catch (error) {
            res.status(401).json({ message: 'Invalid token' });
        }
    });


    // Reset Password
    router.post('/reset-password', async (req, res) => {
        const authHeader = req.headers.authorization;
        const { oldPassword, newPassword } = req.body;

        if (!authHeader) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!);
            const userId = (decoded as any).userId;

            // Fetch the current password hash from the database
            const user = await prisma.user.findUnique({
                where: { id: userId },
            });

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Compare the oldPassword with the user's current password hash
            const isMatch = await bcrypt.compare(oldPassword, user.password);

            if (!isMatch) {
                return res.status(401).json({ message: 'Old password is incorrect' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await prisma.user.update({
                where: { id: userId },
                data: { password: hashedPassword },
            });

            res.json({ message: 'Password reset successfully' });
        } catch (error) {
            res.status(401).json({ message: 'Invalid token' });
        }


    });


    // List All Users
    router.get('/users', async (req, res) => {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                email: true,
                name: true,
                createdAt: true,
                updatedAt: true,
                signUpTimestamp: true,
                loginCount: true,
                logoutTimestamp: true,
            },
        });

        res.json({ users });
    });

    // Get User Statistics
    router.get('/statistics', async (req, res) => {
        try {
            const userCount = await prisma.user.count();

            const activeSessionsToday = await prisma.session.count({
                where: {
                    createdAt: {
                        gte: new Date(new Date().setHours(0, 0, 0, 0)),
                    },
                },
            });

            // Count total sessions
            const totalSessions = await prisma.session.count();

            // Calculate average active sessions for the last 7 days
            const last7DaysSessions = await prisma.session.findMany({
                where: {
                    createdAt: {
                        gte: new Date(new Date().setDate(new Date().getDate() - 7)),
                    },
                },
            });

            const averageActiveSessions = last7DaysSessions.length > 0
                ? last7DaysSessions.length / 7 // Assuming you want average per day
                : 0;

            res.json({
                totalUsers: userCount,
                activeSessionsToday,
                averageActiveSessions,
            });
        } catch (error) {
            console.error('Error fetching user statistics:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    });

    return router;
}
