
import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { db } from "./db";

const COOKIE = "bigdaddy_session";
const SESSION_DURATION = 8 * 60 * 60 * 1000;

// Validate session secret
function secret(): string {
  const value = process.env.SESSION_SECRET;

  if (!value || value.length < 32) {
    throw new Error(
      "SESSION_SECRET must contain at least 32 characters. Check your .env file."
    );
  }

  return value;
}

// Generate secure HMAC signature
function signature(data: string): string {
  return createHmac("sha256", secret())
    .update(data)
    .digest("hex");
}

// Create signed session token
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

// Get currently authenticated admin
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

  if (!payload || !/^[a-f0-9]{64}$/.test(receivedSignature)) {
    return null;
  }

  const expected = Buffer.from(signature(payload), "hex");
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
    maxAge: 8 * 60 * 60,
  };
}

// Validate request origin against allowed application origin
export function checkOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");

  if (!origin) return false;

  try {
    const parsedOrigin = new URL(origin);
    const configuredUrl = process.env.APP_URL;

    if (configuredUrl) {
      const allowed = new URL(configuredUrl);
      return parsedOrigin.origin === allowed.origin;
    }

    // Local development only, without a configured APP_URL
    if (process.env.NODE_ENV !== "production") {
      const host = request.headers.get("host");

      if (!host) return false;

      const hostname = host.split(":")[0];

      if (
        hostname !== "localhost" &&
        hostname !== "127.0.0.1"
      ) {
        return false;
      }

      return parsedOrigin.host === host &&
        (parsedOrigin.protocol === "http:" ||
         parsedOrigin.protocol === "https:");
    }

    return false;
  } catch {
    return false;
  }
}
