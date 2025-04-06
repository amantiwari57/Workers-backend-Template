import { Hono } from "hono";
import { generateToken } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
};

const googleAuth = new Hono<{ Bindings: Env }>();

const REDIRECT_URI = "http://127.0.0.1:8787/api/auth/google/callback";

googleAuth.get("/", (c) => {
  const params = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "email profile",
    access_type: "offline",
    prompt: "consent",
  });

  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

googleAuth.get("/callback", async (c) => {
  const code = c.req.query("code");
  if (!code) return c.json({ error: "No code provided" }, 400);

  // Step 1: Exchange code for access token
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: c.env.GOOGLE_CLIENT_ID,
      client_secret: c.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: "authorization_code",
    }),
  });

  const tokenData = (await tokenRes.json()) as {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
    scope: string;
    token_type: string;
    id_token?: string;
  };

  const access_token = tokenData.access_token;

  if (!access_token) {
    return c.json({ error: "Failed to get access token" }, 401);
  }

  // Step 2: Get user info from Google
  const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: {
      Authorization: `Bearer ${access_token}`,
    },
  });

  const userData = (await userRes.json()) as {
    id: string;
    email: string;
    name: string;
    picture?: string;
  };
  const { email, name } = userData;

  if (!email || !name) {
    return c.json({ error: "Invalid user data from Google" }, 400);
  }

  // Step 3: Check if user exists in DB
  const existingUser = await c.env.DB.prepare(
    "SELECT id FROM users WHERE email = ?"
  )
    .bind(email)
    .first();

  let userId = existingUser?.id;

  // Step 4: If not exists, insert new user
  if (!userId) {
    const result = await c.env.DB.prepare(
      "INSERT INTO users (email, username) VALUES (?, ?, ?)"
    )
      .bind(email, name)
      .run();

    userId = result.meta.last_row_id;
  }

  // Step 5: Generate JWT
  if (!userId) {
    return c.json({ error: "Failed to create user" }, 500);
  }
  const token = await generateToken(userId.toString(), email);

  return c.json({
    message: "Google login successful",
    token,
    user: { id: userId, name, email },
  });
});

export default googleAuth;
