import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { ENV } from './env';
import authRoutes from './auth/routes';

const app = express();

app.use(cors({
  origin: ENV.CORS_ORIGIN === '*' ? true : [ENV.CORS_ORIGIN],
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// Health
app.get('/health', (_req, res) => res.json({ ok: true }));

// Auth
app.use('/auth', authRoutes);

// Protected example
app.get('/me', require('./auth/middleware').requireVendor, (req: any, res) => {
  res.json({ vendorId: req.vendorId });
});

app.listen(ENV.PORT, () => {
  console.log(`csh-auth-2 listening on :${ENV.PORT}`);
});
