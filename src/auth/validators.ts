import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(72),
  displayName: z.string().min(2).max(60).optional(),
  whatsapp: z.string().optional()
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(72)
});
