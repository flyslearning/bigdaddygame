import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { postgres } from "./postgres";

const COOKIE = "bigdaddy_session";
const SESSION_DURATION = 8 * 60 * 60 * 1000;
const PRODUCTION_URL = "https://bigdaddygame.vercel.app";

export type CurrentAdmin = {
  id: number;
  email: string;
  role: string;
};

// node-postgres reads PostgreSQL BIGINT (int8) IDs as strings.
// Never use parseInt(): it may silently truncate malformed or unsafe IDs.
export function adminIdToNumber(value: unknown): number {
  if (typeof value !== "number" && typeof value !== "string") {
    throw new Error("Invalid admin ID");
  }
  if (typeof value === "string" && !/^[1-9]\d*$/.test(value)) {
    throw new Error("Invalid admin ID");
  }
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new Error("Invalid admin ID");
  }
  return id;
}

function secret(): string {
  const value = process.env.SESSION_SECRET;
  if (!value || value.length < 32) {
    throw new Error("Set SESSION_SECRET (at least 32 characters) in Vercel environment variables");
  }
  return value;
}

function signature(payload: string): string {
  return createHmac("sha256", secret()).update(payload).digest("hex");
}

export function createSession(id: number | string): string {
  const adminId = adminIdToNumber(id);
  const payload = Buffer.from(
    JSON.stringify({ id: adminId, exp: Date.now() + SESSION_DURATION })
  ).toString("base64url");
  return `${payload}.${signature(payload)}`;
}

export async function currentAdmin(): Promise<CurrentAdmin | null> {
  const value = (await cookies()).get(COOKIE)?.value;
  if (!value || value.length > 2048) return null;
  const pieces = value.split(".");
  if (pieces.length !== 2) return null;
  const [payload, providedSignature] = pieces;
  if (!payload || !/^[A-Za-z0-9_-]+$/.test(payload) || !/^[0-9a-f]{64}$/.test(providedSignature)) {
    return null;
  }

  // Configuration errors should surface in logs, not be mistaken for invalid cookies.
  const expected = Buffer.from(signature(payload), "hex");
  const provided = Buffer.from(providedSignature, "hex");
  if (provided.length !== expected.length || !timingSafeEqual(expected, provided)) return null;

  let adminId: number;
  try {
    const data: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data || typeof data !== "object") return null;
    const p = data as Record<string, unknown>;
    adminId = adminIdToNumber(p.id);
    if (typeof p.exp !== "number" || !Number.isSafeInteger(p.exp) || Date.now() >= p.exp) return null;
  } catch {
    return null;
  }

  // SELECT id::text is deliberate: BIGINT comes back as a string from pg.
  const result = await postgres().query<{
    id: string;
    email: string;
    role: string;
  }>(
    `SELECT id::text AS id, email, role FROM public.admins
     WHERE id = $1 AND status = 'ACTIVE'`,
    [adminId]
  );
  const admin = result.rows[0];
  if (!admin) return null;
  return { id: adminIdToNumber(admin.id), email: admin.email, role: admin.role };
}

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

export function checkOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const allowed = new Set<string>([new URL(PRODUCTION_URL).origin]);
    if (process.env.APP_URL) allowed.add(new URL(process.env.APP_URL).origin);
    if (process.env.NODE_ENV !== "production") {
      allowed.add("http://localhost:3000");
      allowed.add("http://127.0.0.1:3000");
    }
    return allowed.has(new URL(origin).origin);
  } catch {
    return false;
  }
}
