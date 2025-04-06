import { z } from "zod";
export const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const UserSchema = z.object({
  username: z.string().min(1, { message: "Username is required" }),
  email: z.string().regex(emailRegex, { message: "Invalid email address" }),
  password: z.string().min(8, { message: "Password must be at least 8 characters long" }),
});
