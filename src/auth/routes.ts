import { Router } from 'express';
import { register, login, refresh, logout } from './controller';
import { requireVendor } from './middleware';

const r = Router();

r.post('/register', register);
r.post('/login',    login);
r.post('/refresh',  refresh);
r.post('/logout',   logout);

// test a protected route here or in server.ts
r.get('/whoami', requireVendor, (req: any, res) => res.json({ vendorId: req.vendorId }));

export default r;
