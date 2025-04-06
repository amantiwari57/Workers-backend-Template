// signup.ts
import { Hono } from "hono";
import { z } from "zod";
import { UserSchema } from "../../validators/userValidation";
import { hashPassword, verifyPassword } from "../../utils/passwordHash";
import { generateToken } from "../../utils/jwtHandler";


// Environment type for D1 database
export type Env = {
  DB: D1Database; // D1 database binding
};

// Hono app with D1 bindings
const signup = new Hono<{ Bindings: Env }>();

// Signup route
signup.post("/", async (c) => {
  try {
    // Parse and validate request body
    const body = await c.req.json();
    const result = UserSchema.safeParse(body);

    if (!result.success) {
      return c.json({ error: result.error.errors }, 400); // Bad request
    }

    const { username, email, password } = result.data;

    // Check if email or username already exists
    const existingUserStmt = c.env.DB.prepare(
      "SELECT * FROM users WHERE email = ? OR username = ?"
    ).bind(email, username);
    const existingUser = await existingUserStmt.all();

    if (existingUser.results && existingUser.results.length > 0) {
      return c.json({ error: "Email or username already taken" }, 409); // Conflict
    }

    // Hash the password (salt and hash combined)
    const hashedPassword = hashPassword(password);

    // Insert the new user into the database
    const insertStmt = c.env.DB.prepare(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?) RETURNING id, username, email, created_at"
    ).bind(username, email, hashedPassword);

    const res = await insertStmt.first(); // Get the inserted row

  

    if (!res|| !res.id) {
      throw new Error("Failed to insert user");
    }

    const token = await generateToken(res?.id.toString(), email); // Generate JWT token
    // Return the created user (excluding password)
    return c.json(
      {
        message: "User created successfully",
        user: res,
        token:token,
      },
      201 // Created
    );
  } catch (error) {
    console.error("Signup error:", error);
    return c.json({ error: "Internal server error" }, 500);
  }
});



export default signup;