import { Hono } from "hono";
import { z } from "zod";
import { UserSchema } from "../../validators/userValidation";
import { hashPassword } from "../../utils/passwordHash";
import { generateTokenPair } from "../../utils/jwtHandler";
import { sendOtpEmail } from "../../utils/nodemailer";

// Environment type for D1 database
export type Env = {
  DB: D1Database;
  SMTP_USER: string;
  API_KEY: string;
};

// Hono app
const signup = new Hono<{ Bindings: Env }>();

// Utility to generate random 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// --- SIGNUP Route (no JWT here) ---
signup.post("/", async (c) => {
  try {
    const body = await c.req.json();
    const result = UserSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400);
    }

    const { username, email, password } = result.data;

    // Check if user exists
    const existingUserStmt = c.env.DB.prepare(
      "SELECT * FROM users WHERE email = ? OR username = ?"
    ).bind(email, username);
    const existingUser = await existingUserStmt.all();

    if (existingUser.results && existingUser.results.length > 0) {
      return c.json({ error: "Email or username already taken" }, 409);
    }

    const hashedPassword = hashPassword(password);

    // Insert user with default role
    const insertStmt = c.env.DB.prepare(
      "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?) RETURNING id, username, email, role, created_at"
    ).bind(username, email, hashedPassword, "user");
    const res = await insertStmt.first();

    if (!res || !res.id) {
      throw new Error("Failed to insert user");
    }

    // Generate OTP
    const otp = generateOTP();
    const otpInsert = c.env.DB.prepare(
      "INSERT INTO user_otps (user_id, otp) VALUES (?, ?)"
    ).bind(res.id, otp);
    await otpInsert.run();
    await sendOtpEmail(c.env, email, otp);

    return c.json(
      {
        message: "User created successfully. OTP sent for verification.",
        user: {
          id: res.id,
          username: res.username,
          email: res.email,
          role: res.role,
        },
      },
      201
    );
  } catch (error) {
    console.error("Signup error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

// --- VERIFY OTP Route (generate JWT here) ---
const VerifyOtpSchema = z.object({
  email: z.string().email(),
  otp: z.string().length(6),
});

signup.post("/verify-otp", async (c) => {
  try {
    const body = await c.req.json();
    const result = VerifyOtpSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400);
    }

    const { email, otp } = result.data;

    // Fetch user by email
    const userStmt = c.env.DB.prepare(
      "SELECT id, username, email, role FROM users WHERE email = ?"
    ).bind(email);
    const user = await userStmt.first();

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    const { id: userId } = user as { id: number };

    // Validate OTP
    const otpStmt = c.env.DB.prepare(
      `SELECT * FROM user_otps 
       WHERE user_id = ? AND otp = ? AND expires_at > CURRENT_TIMESTAMP`
    ).bind(userId, otp);
    const otpRecord = await otpStmt.first();

    if (!otpRecord) {
      return c.json({ error: "Invalid or expired OTP" }, 400);
    }

    // OTP valid, generate token pair
    const tokens = await generateTokenPair(userId.toString(), email, user.role as string);

    // Optionally delete used OTP
    const deleteOtpStmt = c.env.DB.prepare(
      "DELETE FROM user_otps WHERE id = ?"
    ).bind((otpRecord as any).id);
    await deleteOtpStmt.run();

    return c.json({
      message: "OTP verified successfully",
      ...tokens,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role || "user",
        created_at: user.created_at,
      },
    }, 200);
  } catch (error) {
    console.error("OTP verification error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

export default signup;
