import { Jwt } from "hono/utils/jwt";

const secret = "your-secret-key"; // Replace this with your actual secret

export const generateToken = async (userId: string, email: string) => {
  const token = await Jwt.sign(
    {
      userId,
      email,
    },
    secret
  );
  return token;
};

export const verifyToken = async (token: string) => {
    try {
      const payload = await Jwt.verify(token, secret);
  
      if (!payload || typeof payload !== "object") {
        throw new Error("Invalid token payload");
      }
  
      const userId = payload.sub as string;
      const email = payload.email as string;
  
      return { userId, email };
    } catch (error) {
      console.error("Token verification failed:", error);
      throw new Error("Unauthorized");
    }}