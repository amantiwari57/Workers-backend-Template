import { Hono } from "hono";
import { z } from "zod";
import { sendOtpEmail } from "../../utils/nodemailer";

export type Env = {
  DB: D1Database;
  SMTP_USER: string;
  API_KEY: string;
};

const forgotPassword = new Hono<{ Bindings: Env }>();

// Utility to generate random 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

const ForgotPasswordSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
});

const ResetPasswordSchema = z.object({
  email: z.string().email({ message: "Invalid email address" }),
  otp: z.string().length(6, { message: "OTP must be 6 digits" }),
  newPassword: z.string().min(8, { message: "Password must be at least 8 characters long" }),
});

// Request password reset
forgotPassword.post("/request", async (c) => {
  try {
    const body = await c.req.json();
    const result = ForgotPasswordSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400);
    }

    const { email } = result.data;

    // Check if user exists
    const userStmt = c.env.DB
      .prepare("SELECT id FROM users WHERE email = ?")
      .bind(email);
    const user = await userStmt.first();

    if (!user) {
      // Don't reveal if user exists or not for security
      return c.json({ 
        message: "If the email exists, a password reset OTP has been sent." 
      }, 200);
    }

    // Generate OTP
    const otp = generateOTP();
    
    // Store OTP in database with expiration
    const otpInsert = c.env.DB.prepare(
      "INSERT INTO user_otps (user_id, otp, type) VALUES (?, ?, ?)"
    ).bind(user.id, otp, "password_reset");
    await otpInsert.run();

    // Send OTP via email
    await sendOtpEmail(c.env, email, otp, "Password Reset");

    return c.json({
      message: "If the email exists, a password reset OTP has been sent.",
    }, 200);
  } catch (error) {
    console.error("Forgot password error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// Reset password with OTP
forgotPassword.post("/reset", async (c) => {
  try {
    const body = await c.req.json();
    const result = ResetPasswordSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400);
    }

    const { email, otp, newPassword } = result.data;

    // Get user by email
    const userStmt = c.env.DB
      .prepare("SELECT id FROM users WHERE email = ?")
      .bind(email);
    const user = await userStmt.first();

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    // Validate OTP
    const otpStmt = c.env.DB.prepare(
      `SELECT * FROM user_otps 
       WHERE user_id = ? AND otp = ? AND type = ? AND expires_at > CURRENT_TIMESTAMP`
    ).bind(user.id, otp, "password_reset");
    const otpRecord = await otpStmt.first();

    if (!otpRecord) {
      return c.json({ error: "Invalid or expired OTP" }, 400);
    }

    // Hash new password
    const { hashPassword } = await import("../../utils/passwordHash");
    const hashedPassword = hashPassword(newPassword);

    // Update password
    const updateStmt = c.env.DB
      .prepare("UPDATE users SET password = ? WHERE id = ?")
      .bind(hashedPassword, user.id);
    await updateStmt.run();

    // Delete used OTP
    const deleteOtpStmt = c.env.DB
      .prepare("DELETE FROM user_otps WHERE id = ?")
      .bind((otpRecord as any).id);
    await deleteOtpStmt.run();

    return c.json({
      message: "Password reset successfully",
    }, 200);
  } catch (error) {
    console.error("Reset password error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

export default forgotPassword; 