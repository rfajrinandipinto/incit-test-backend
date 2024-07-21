import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: '/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const user = await prisma.user.upsert({
            where: { email: profile.emails![0].value },
            update: {
                name: profile.displayName,
                googleId: profile.id,
            },
            create: {
                email: profile.emails![0].value,
                name: profile.displayName,
                googleId: profile.id,
                password: '', // Can be an empty string or some default value
            },
        });
        done(null, user);
    } catch (error) {
        done(error);
    }
}));

passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id: number, done) => {
    try {
        const user = await prisma.user.findUnique({ where: { id } });
        done(null, user);
    } catch (error) {
        done(error);
    }
});
