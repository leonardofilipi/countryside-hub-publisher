import { prisma } from '../prisma';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { ENV } from '../env';
import { registerSchema, loginSchema } from './validators';
import { addDays } from 'date-fns';
import { Request, Response } from 'express';
import { v4 as uuid } from 'uuid';

function setAuthCookies(res: Response, access: string, refresh: string) {
  const common = {
    httpOnly: true,
    secure: ENV.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    domain: ENV.COOKIE_DOMAIN,
    path: '/'
  };
  res.cookie('access_token', access, { ...common, maxAge: 1000 * 60 * 15 });         // 15m
  res.cookie('refresh_token', refresh, { ...common, maxAge: 1000 * 60 * 60 * 24 * 30 }); // 30d
}

export async function register(req: Request, res: Response) {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input', details: parsed.error.flatten() });
  const { email, password, displayName, whatsapp } = parsed.data;

  const exists = await prisma.vendor.findUnique({ where: { email } });
  if (exists) return res.status(409).json({ error: 'email_in_use' });

  const passwordHash = await bcrypt.hash(password, 12);

  const vendor = await prisma.vendor.create({
    data: { email, passwordHash, displayName, whatsapp, status: 'PENDING' }
  });

  // TODO: send verification email via Zoho/Postmark
  return res.status(201).json({ id: vendor.id, email: vendor.email, status: vendor.status });
}

export async function login(req: Request, res: Response) {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input', details: parsed.error.flatten() });
  const { email, password } = parsed.data;

  const v = await prisma.vendor.findUnique({ where: { email } });
  if (!v) return res.status(401).json({ error: 'invalid_credentials' });

  const ok = await bcrypt.compare(password, v.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  // Optional: block if suspended
  if (v.status === 'SUSPENDED') return res.status(403).json({ error: 'account_suspended' });

  const access = jwt.sign({ sub: v.id, role: 'vendor' }, ENV.JWT_SECRET, { expiresIn: '15m' });
  const refreshTokenValue = uuid();
  const refreshExp = addDays(new Date(), 30);

  await prisma.refreshToken.create({
    data: { vendorId: v.id, token: refreshTokenValue, expiresAt: refreshExp }
  });

  const refresh = jwt.sign({ sub: v.id, jti: refreshTokenValue }, ENV.JWT_REFRESH_SECRET, { expiresIn: '30d' });

  setAuthCookies(res, access, refresh);
  return res.json({ ok: true });
}

export async function refresh(req: Request, res: Response) {
  const token = req.cookies?.refresh_token;
  if (!token) return res.status(401).json({ error: 'refresh_missing' });

  try {
    const payload = jwt.verify(token, ENV.JWT_REFRESH_SECRET) as { sub: string; jti: string };
    const stored = await prisma.refreshToken.findUnique({ where: { token: payload.jti } });
    if (!stored || stored.vendorId !== payload.sub || stored.expiresAt < new Date()) {
      return res.status(401).json({ error: 'refresh_invalid' });
    }

    const access = jwt.sign({ sub: payload.sub, role: 'vendor' }, ENV.JWT_SECRET, { expiresIn: '15m' });
    // rotate refresh token (best practice)
    await prisma.refreshToken.delete({ where: { token: payload.jti } });
    const newJti = uuid();
    const newExp = addDays(new Date(), 30);
    await prisma.refreshToken.create({ data: { vendorId: payload.sub, token: newJti, expiresAt: newExp } });
    const refresh = jwt.sign({ sub: payload.sub, jti: newJti }, ENV.JWT_REFRESH_SECRET, { expiresIn: '30d' });

    setAuthCookies(res, access, refresh);
    return res.json({ ok: true });
  } catch {
    return res.status(401).json({ error: 'refresh_invalid' });
  }
}

export async function logout(req: Request, res: Response) {
  const token = req.cookies?.refresh_token;
  if (token) {
    try {
      const payload = jwt.verify(token, ENV.JWT_REFRESH_SECRET) as { jti: string };
      await prisma.refreshToken.delete({ where: { token: payload.jti } }).catch(() => {});
    } catch {}
  }
  res.clearCookie('access_token', { path: '/', domain: ENV.COOKIE_DOMAIN });
  res.clearCookie('refresh_token', { path: '/', domain: ENV.COOKIE_DOMAIN });
  return res.json({ ok: true });
}
