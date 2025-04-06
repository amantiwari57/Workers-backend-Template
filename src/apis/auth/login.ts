import { Hono } from "hono";
import { z } from "zod";
import { verifyPassword } from "../../utils/passwordHash";
import { generateToken } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
};

const LoginSchema = z.object({
  email: z
    .string()
    .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, { message: "Invalid email address" }),
  password: z
    .string()
    .min(8, { message: "Password must be at least 8 characters long" }),
});

const login = new Hono<{ Bindings: Env }>();

login.post("/", async (c) => {
  try {
    const body = await c.req.json();
    const result = LoginSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400);
    }

    const { email, password } = result.data;

    // ✅ Fix: Select `id` along with `password`
    const userStmt = c.env.DB
      .prepare("SELECT id, password FROM users WHERE email = ?")
      .bind(email);
    const user = await userStmt.first<{ id: number; password: string }>();

    if (!user) {
      return c.json({ error: "Invalid email or password" }, 401);
    }

    const isValid = verifyPassword(password, user.password);
    if (!isValid) {
      return c.json({ error: "Invalid email or password" }, 401);
    }

    const token = await generateToken(user.id.toString(), email);

    return c.json(
      {
        message: "Login successful",
        token,
        user: {
            id: user.id,
            email,
          },
      },
      200
    );
  } catch (error) {
    console.error("Login error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});

export default login;
