
import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { db } from "./db";

// BigDaddy GAME Authentication Configuration

const COOKIE = "bigdaddy_session";

const SESSION_DURATION = 8 * 60 * 60 * 1000;

// Official production URL
const PRODUCTION_URL = "https://bigdaddygame.vercel.app";

// Validate session secret
function secret(): string {
  const value = process.env.SESSION_SECRET;

  if (!value || value.length < 32) {
    throw new Error(
      "SESSION_SECRET must contain at least 32 characters. Check Vercel environment variables."
    );
  }

  return value;
}

// Generate HMAC SHA-256 signature
function signature(data: string): string {
  return createHmac("sha256", secret())
    .update(data)
    .digest("hex");
}

// Create secure session
export function createSession(id: number): string {
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new Error("Invalid admin ID");
  }

  const payload = Buffer.from(
    JSON.stringify({
      id,
      exp: Date.now() + SESSION_DURATION,
    })
  ).toString("base64url");

  return `${payload}.${signature(payload)}`;
}

// Get logged-in admin
export async function currentAdmin(): Promise<{
  id: number;
  email: string;
  role: string;
} | null> {
  const value = (await cookies()).get(COOKIE)?.value;

  if (!value) return null;

  const parts = value.split(".");

  if (parts.length !== 2) return null;

  const [payload, receivedSignature] = parts;

  if (
    !payload ||
    !/^[a-f0-9]{64}$/.test(receivedSignature)
  ) {
    return null;
  }

  let expected: Buffer;

  try {
    expected = Buffer.from(signature(payload), "hex");
  } catch {
    return null;
  }

  const received = Buffer.from(receivedSignature, "hex");

  if (
    expected.length !== received.length ||
    !timingSafeEqual(expected, received)
  ) {
    return null;
  }

  try {
    const decoded = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (
      !decoded ||
      !Number.isSafeInteger(decoded.id) ||
      decoded.id <= 0 ||
      typeof decoded.exp !== "number" ||
      !Number.isFinite(decoded.exp) ||
      Date.now() >= decoded.exp
    ) {
      return null;
    }

    const admin = db()
      .prepare(
        "SELECT id, email, role FROM admins WHERE id = ?"
      )
      .get(decoded.id) as
      | {
          id: number;
          email: string;
          role: string;
        }
      | undefined;

    return admin ?? null;
  } catch {
    return null;
  }
}

// Secure session cookie
export function sessionCookie(value: string) {
  return {
    name: COOKIE,
    value,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict" as const,
    path: "/",
    maxAge: Math.floor(SESSION_DURATION / 1000),
  };
}

// Validate request origin
export function checkOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");

  if (!origin) {
    return false;
  }

  try {
    const requestOrigin = new URL(origin).origin;

    // Production domain is always allowed
    const allowedOrigins: string[] = [
      new URL(PRODUCTION_URL).origin,
    ];

    // Optional custom domain
    const configuredUrl = process.env.APP_URL;

    if (configuredUrl) {
      allowedOrigins.push(
        new URL(configuredUrl).origin
      );
    }

    // Development environments
    if (process.env.NODE_ENV !== "production") {
      allowedOrigins.push(
        "http://localhost:3000",
        "http://127.0.0.1:3000"
      );
    }

    return allowedOrigins.includes(requestOrigin);
  } catch (error) {
    console.error("Origin validation error:", error);
    return false;
  }
}
