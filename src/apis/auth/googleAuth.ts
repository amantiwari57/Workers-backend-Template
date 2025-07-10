import { Hono } from "hono";
import { OAuth2Client } from "google-auth-library";
import { generateTokenPair } from "../../utils/jwtHandler";

export type Env = {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_REDIRECT_URI?: string; // Optional environment variable
};

const googleAuth = new Hono<{ Bindings: Env }>();

googleAuth.get("/", (c) => {
  // Use environment variable if available, otherwise construct from request
  const redirectUri = c.env.GOOGLE_REDIRECT_URI || 
    `${c.req.url.split('/auth/google')[0]}/api/auth/google/callback`;
  
  const oauth2Client = new OAuth2Client(
    c.env.GOOGLE_CLIENT_ID,
    c.env.GOOGLE_CLIENT_SECRET,
    redirectUri
  );

  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: [
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email",
    ],
    prompt: "consent",
  });

  return c.redirect(authUrl);
});

googleAuth.get("/callback", async (c) => {
  const code = c.req.query("code");
  if (!code) return c.json({ error: "No code provided" }, 400);

  try {
    // Use environment variable if available, otherwise construct from request
    const redirectUri = c.env.GOOGLE_REDIRECT_URI || 
      `${c.req.url.split('/auth/google/callback')[0]}/api/auth/google/callback`;
    
    // Create OAuth2 client
    const oauth2Client = new OAuth2Client(
      c.env.GOOGLE_CLIENT_ID,
      c.env.GOOGLE_CLIENT_SECRET,
      redirectUri
    );

    // Exchange code for tokens
    const { tokens: googleTokens } = await oauth2Client.getToken(code);
    
    if (!googleTokens.access_token) {
      return c.json({ error: "Failed to get access token" }, 401);
    }

    // Get user info from Google
    const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: {
        Authorization: `Bearer ${googleTokens.access_token}`,
      },
    });

    if (!userRes.ok) {
      return c.json({ error: "Failed to get user info from Google" }, 401);
    }

    const userData = await userRes.json() as {
      id: string;
      email: string;
      name: string;
      picture?: string;
    };

    const { email, name, picture } = userData;

    if (!email || !name) {
      return c.json({ error: "Invalid user data from Google" }, 400);
    }

    // Check if user exists in DB
    const existingUser = await c.env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    )
      .bind(email)
      .first();

    let userId = existingUser?.id;

    // If not exists, insert new user
    if (!userId) {
      const result = await c.env.DB.prepare(
        "INSERT INTO users (email, username) VALUES (?, ?)"
      )
        .bind(email, name)
        .run();

      userId = result.meta.last_row_id;
    }

    // Generate JWT
    if (!userId) {
      return c.json({ error: "Failed to create user" }, 500);
    }
    
    const tokens = await generateTokenPair(userId.toString(), email, "user");

    return c.json({
      message: "Google login successful",
      ...tokens,
      user: { 
        id: userId, 
        name, 
        email,
        picture,
        role: "user"
      },
    });

  } catch (error) {
    console.error("Google OAuth error:", error);
    return c.json({ 
      error: "Failed to authenticate with Google",
      details: error instanceof Error ? error.message : "Unknown error"
    }, 500);
  }
});

export default googleAuth;
