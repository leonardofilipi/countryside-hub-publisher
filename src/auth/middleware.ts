import jwt from 'jsonwebtoken';
import { ENV } from '../env';

export function requireVendor(req: any, res: any, next: any) {
  const token = req.cookies?.access_token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
  if (!token) return res.status(401).json({ error: 'auth_required' });
  try {
    const payload = jwt.verify(token, ENV.JWT_SECRET) as { sub: string; role?: string };
    req.vendorId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}
