
import { Pool, PoolClient } from "pg";

// BigDaddy GAME — Supabase PostgreSQL

const globalForDb = globalThis as unknown as {
  bigDaddyPool?: Pool;
};

// PostgreSQL connection
export function postgres(): Pool {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error(
      "DATABASE_URL is missing. Check your environment variables."
    );
  }

  if (!globalForDb.bigDaddyPool) {
    globalForDb.bigDaddyPool = new Pool({
      connectionString: databaseUrl,
      max: 2,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000,
    });

    globalForDb.bigDaddyPool.on("error", (error) => {
      console.error(
        "[BigDaddy GAME] PostgreSQL Error:",
        error.message
      );
    });
  }

  return globalForDb.bigDaddyPool;
}

// Save Admin Activity Logs
export async function auditLog(
  adminId: number,
  action: string,
  details: Record<string, unknown>,
  client?: PoolClient
): Promise<void> {
  const connection = client ?? postgres();

  await connection.query(
    `INSERT INTO public.audit_logs
      (admin_id, action, details)
     VALUES ($1, $2, $3::jsonb)`,
    [
      adminId,
      action,
      JSON.stringify(details),
    ]
  );
}
