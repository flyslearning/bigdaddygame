
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import bcrypt from "bcryptjs";

import {
  currentAdmin,
  createSession,
  sessionCookie,
  checkOrigin,
  adminIdToNumber,
} from "@/lib/auth";

import { postgres, auditLog } from "@/lib/postgres";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Ctx = {
  params: Promise<{ route: string[] }>;
};

type Admin = {
  id: number;
  email: string;
  role: string;
};

const ok = (data: unknown, status = 200) =>
  NextResponse.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });

const bad = (message: string, status = 400) =>
  ok({ error: message }, status);

function can(
  admin: Admin,
  action: "PLAYERS" | "POINTS" | "GAMES" |
    "FINANCE" | "WALLETS" | "PAYOUTS"
): boolean {
  if (admin.role === "SUPER_ADMIN") return true;

  if (admin.role === "GAME_MANAGER") {
    return ["PLAYERS", "POINTS", "GAMES"].includes(action);
  }

  if (admin.role === "FINANCE_ADMIN") {
    return ["FINANCE", "PAYOUTS"].includes(action);
  }

  return false;
}

function addressValid(network: string, address: string) {
  if (network === "ERC20") {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
  }

  if (network === "TRC20") {
    return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address);
  }

  return false;
}

function errorResponse(error: unknown) {
  if (error instanceof z.ZodError) {
    return bad(
      error.issues
        .map((i) => `${i.path.join(".")}: ${i.message}`)
        .join("; ")
    );
  }

  if (error instanceof Error) {
    const pgError = error as Error & { code?: string };

    if (pgError.code === "23505") {
      return bad("Record already exists", 409);
    }

    if (pgError.code === "23503") {
      return bad("Referenced record does not exist");
    }

    if (
      [
        "Active player Game ID not found",
        "Insufficient points",
        "Choose an active wallet",
      ].includes(error.message)
    ) {
      return bad(error.message);
    }
  }

  console.error("BigDaddy GAME API Error:", error);
  return bad("Server error", 500);
}

// --------------------------------------------------
// GET ROUTES
// --------------------------------------------------

export async function GET(
  _req: NextRequest,
  ctx: Ctx
) {
  try {
    const route = (await ctx.params).route.join("/");
    const admin = await currentAdmin();

    if (route === "me") {
      return ok({ admin });
    }

    if (!admin) {
      return bad("Unauthorized", 401);
    }

    const db = postgres();

    // Dashboard overview
    if (route === "overview") {
      const [playersResult, gamesResult, figuresResult,
        activityResult, dailyResult] = await Promise.all([
        db.query(`
          SELECT
            COUNT(*)::integer AS n,
            COALESCE(SUM(points),0)::bigint AS points
          FROM players
        `),

        db.query(`
          SELECT COUNT(*)::integer AS n
          FROM games
        `),

        db.query(`
          SELECT
            entry_type,
            SUM(amount_cents)::bigint AS total,
            COUNT(*)::integer AS count
          FROM entries
          GROUP BY entry_type
        `),

        db.query(`
          SELECT
            l.id,l.action,l.details,l.created_at,a.email
          FROM audit_logs l
          LEFT JOIN admins a ON a.id=l.admin_id
          ORDER BY l.id DESC
          LIMIT 12
        `),

        db.query(`
          SELECT
            TO_CHAR(created_at AT TIME ZONE 'UTC',
              'YYYY-MM-DD') AS day,
            entry_type,
            SUM(amount_cents)::bigint AS amount
          FROM entries
          GROUP BY 1,2
          ORDER BY day DESC
          LIMIT 60
        `),
      ]);

      return ok({
        players: {
          n: playersResult.rows[0].n,
          points: Number(playersResult.rows[0].points),
        },
        games: gamesResult.rows[0],
        figures: figuresResult.rows.map((row) => ({
          ...row,
          total: Number(row.total),
        })),
        activity: activityResult.rows,
        daily: dailyResult.rows.map((row) => ({
          ...row,
          amount: Number(row.amount),
        })),
      });
    }

    // Players
    if (route === "players") {
      const result = await db.query(
        `SELECT * FROM players ORDER BY id DESC LIMIT 500`
      );
      return ok(result.rows);
    }

    // Games
    if (route === "games") {
      const result = await db.query(
        `SELECT * FROM games ORDER BY id DESC`
      );
      return ok(result.rows);
    }

    // Point history
    if (route === "points") {
      const result = await db.query(`
        SELECT p.game_id,p.name,l.*
        FROM points_ledger l
        JOIN players p ON p.id=l.player_id
        ORDER BY l.id DESC
        LIMIT 300
      `);

      return ok(result.rows);
    }

    // Accounting entries
    if (route === "entries") {
      if (!can(admin, "FINANCE")) {
        return bad("Forbidden", 403);
      }

      const result = await db.query(
        `SELECT * FROM entries ORDER BY id DESC LIMIT 500`
      );

      return ok(result.rows.map((row) => ({
        ...row,
        amount_cents: Number(row.amount_cents),
      })));
    }

    // Wallets
    if (route === "wallets") {
      if (!can(admin, "FINANCE") &&
          !can(admin, "WALLETS")) {
        return bad("Forbidden", 403);
      }

      const result = await db.query(
        `SELECT * FROM wallet_addresses ORDER BY id DESC`
      );

      return ok(result.rows);
    }

    // Payout drafts
    if (route === "payouts") {
      if (!can(admin, "PAYOUTS")) {
        return bad("Forbidden", 403);
      }

      const result = await db.query(`
        SELECT p.*,w.label,w.network,w.address
        FROM payout_requests p
        JOIN wallet_addresses w ON w.id=p.wallet_id
        ORDER BY p.id DESC
      `);

      return ok(result.rows);
    }

    // Audit history
    if (route === "audit") {
      if (admin.role !== "SUPER_ADMIN") {
        return bad("Forbidden", 403);
      }

      const result = await db.query(`
        SELECT l.*,a.email
        FROM audit_logs l
        LEFT JOIN admins a ON a.id=l.admin_id
        ORDER BY l.id DESC
        LIMIT 300
      `);

      return ok(result.rows);
    }

    return bad("Not found", 404);
  } catch (error) {
    return errorResponse(error);
  }
}

// --------------------------------------------------
// POST ROUTES
// --------------------------------------------------

export async function POST(
  req: NextRequest,
  ctx: Ctx
) {
  try {
    if (!checkOrigin(req)) {
      return bad("Invalid origin", 403);
    }

    const route = (await ctx.params).route.join("/");
    const body = await req.json();

    const database = postgres();

    // ADMIN LOGIN
    if (route === "login") {
      const v = z.object({
        email: z.string().email(),
        password: z.string().min(1),
      }).parse(body);

      const result = await database.query<{
        id: string;
        pass_hash: string;
      }>(
        `SELECT id::text AS id,pass_hash
         FROM admins
         WHERE email=$1 AND status='ACTIVE'`,
        [v.email.trim().toLowerCase()]
      );

      const account = result.rows[0];

      if (
        !account ||
        !(await bcrypt.compare(
          v.password,
          account.pass_hash
        ))
      ) {
        return bad("Invalid credentials", 401);
      }

      const response = ok({ success: true });

      const adminId = adminIdToNumber(account.id);
      response.cookies.set(sessionCookie(createSession(adminId)));
      await auditLog(adminId, "LOGIN", {});

      return response;
    }

    // Authenticate all other POST routes
    const admin = await currentAdmin();

    if (!admin) {
      return bad("Unauthorized", 401);
    }

    // LOGOUT
    if (route === "logout") {
      const response = ok({ success: true });

      response.cookies.set({
        ...sessionCookie(""),
        maxAge: 0,
      });

      return response;
    }

    // CREATE PLAYER
    if (route === "players") {
      if (!can(admin, "PLAYERS")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        game_id: z.string().regex(
          /^[A-Za-z0-9_-]{3,32}$/
        ),
        name: z.string().trim().min(2).max(80),
      }).parse(body);

      const result = await database.query(
        `INSERT INTO players (game_id,name)
         VALUES ($1,$2)
         RETURNING id`,
        [v.game_id, v.name]
      );

      await auditLog(admin.id, "CREATE_PLAYER", {
        id: result.rows[0].id,
        ...v,
      });

      return ok({ success: true }, 201);
    }

    // ADD / DEDUCT POINTS
    if (route === "points") {
      if (!can(admin, "POINTS")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        game_id: z.string().min(3),
        delta: z.number()
          .int()
          .min(-1000000)
          .max(1000000)
          .refine((x) => x !== 0),
        reason: z.string().trim().min(5).max(200),
      }).parse(body);

      const client = await database.connect();

      try {
        await client.query("BEGIN");

        const playerResult = await client.query<{
          id: string | number;
          points: number;
        }>(
          `SELECT id,points
           FROM players
           WHERE game_id=$1 AND status='ACTIVE'
           FOR UPDATE`,
          [v.game_id]
        );

        const player = playerResult.rows[0];

        if (!player) {
          throw new Error(
            "Active player Game ID not found"
          );
        }

        const after = Number(player.points) + v.delta;

        if (after < 0) {
          throw new Error("Insufficient points");
        }

        await client.query(
          `UPDATE players
           SET points=$1 WHERE id=$2`,
          [after, player.id]
        );

        const ledger = await client.query(
          `INSERT INTO points_ledger
           (player_id,delta,balance_after,reason,admin_id)
           VALUES ($1,$2,$3,$4,$5)
           RETURNING id`,
          [
            player.id,
            v.delta,
            after,
            v.reason,
            admin.id,
          ]
        );

        await auditLog(
          admin.id,
          "POINT_ADJUST",
          {
            ledger_id: ledger.rows[0].id,
            game_id: v.game_id,
            delta: v.delta,
            after,
          },
          client
        );

        await client.query("COMMIT");

        return ok({
          success: true,
          after,
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }

    // CREATE GAME
    if (route === "games") {
      if (!can(admin, "GAMES")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        title: z.string().trim().min(2).max(80),
        slug: z.string().regex(
          /^[a-z0-9-]{3,40}$/
        ),
        category: z.string().trim().min(2).max(50),
      }).parse(body);

      const result = await database.query(
        `INSERT INTO games (title,slug,category)
         VALUES ($1,$2,$3)
         RETURNING id`,
        [v.title, v.slug, v.category]
      );

      await auditLog(admin.id, "CREATE_GAME", {
        id: result.rows[0].id,
        ...v,
      });

      return ok({ success: true }, 201);
    }

    // GAME STATUS
    if (route === "games/status") {
      if (!can(admin, "GAMES")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        id: z.number().int().positive(),
        status: z.enum(["ACTIVE", "DISABLED"]),
      }).parse(body);

      const result = await database.query(
        `UPDATE games SET status=$1
         WHERE id=$2 RETURNING id`,
        [v.status, v.id]
      );

      if (!result.rowCount) {
        return bad("Game not found", 404);
      }

      await auditLog(admin.id, "GAME_STATUS", v);

      return ok({ success: true });
    }

    // ACCOUNTING ENTRY
    if (route === "entries") {
      if (!can(admin, "FINANCE")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        entry_type: z.enum([
          "REVENUE",
          "EXPENSE",
          "DEPOSIT",
          "REFUND",
        ]),
        amount: z.number().positive().max(1e9),
        memo: z.string().trim().min(3).max(200),
        reference: z.string().max(100).optional(),
      }).parse(body);

      const cents = Math.round(v.amount * 100);

      const result = await database.query(
        `INSERT INTO entries
         (entry_type,amount_cents,memo,reference,admin_id)
         VALUES ($1,$2,$3,$4,$5)
         RETURNING id`,
        [
          v.entry_type,
          cents,
          v.memo,
          v.reference ?? null,
          admin.id,
        ]
      );

      await auditLog(admin.id, "ACCOUNTING_ENTRY", {
        id: result.rows[0].id,
        entry_type: v.entry_type,
        amount_cents: cents,
      });

      return ok({ success: true }, 201);
    }

    // ADD WALLET ADDRESS
    if (route === "wallets") {
      if (!can(admin, "WALLETS")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        label: z.string().trim().min(2).max(60),
        network: z.enum(["ERC20", "TRC20"]),
        address: z.string().trim(),
      }).parse(body);

      if (!addressValid(v.network, v.address)) {
        return bad("Invalid wallet address format");
      }

      const result = await database.query(
        `INSERT INTO wallet_addresses
         (label,network,address,admin_id)
         VALUES ($1,$2,$3,$4)
         RETURNING id`,
        [
          v.label,
          v.network,
          v.address,
          admin.id,
        ]
      );

      await auditLog(admin.id, "WALLET_ADDED", {
        wallet_id: result.rows[0].id,
        network: v.network,
        address: v.address,
      });

      return ok({ success: true }, 201);
    }

    // DEACTIVATE WALLET
    if (route === "wallets/deactivate") {
      if (!can(admin, "WALLETS")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        id: z.number().int().positive(),
      }).parse(body);

      const result = await database.query(
        `UPDATE wallet_addresses
         SET active=0 WHERE id=$1
         RETURNING id`,
        [v.id]
      );

      if (!result.rowCount) {
        return bad("Wallet not found", 404);
      }

      await auditLog(
        admin.id,
        "WALLET_DISABLED",
        v
      );

      return ok({ success: true });
    }

    // CREATE PAYOUT DRAFT
    // Does not execute blockchain transactions.
    if (route === "payouts") {
      if (!can(admin, "PAYOUTS")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        wallet_id: z.number().int().positive(),
        amount_usdt: z.string().regex(
          /^(?:[1-9]\d{0,11})(?:\.\d{1,6})?$/
        ),
        note: z.string().max(200).optional(),
      }).parse(body);

      const wallet = await database.query(
        `SELECT id FROM wallet_addresses
         WHERE id=$1 AND active=1`,
        [v.wallet_id]
      );

      if (!wallet.rowCount) {
        throw new Error("Choose an active wallet");
      }

      const result = await database.query(
        `INSERT INTO payout_requests
         (wallet_id,amount_usdt,note,admin_id)
         VALUES ($1,$2,$3,$4)
         RETURNING id`,
        [
          v.wallet_id,
          v.amount_usdt,
          v.note ?? null,
          admin.id,
        ]
      );

      await auditLog(
        admin.id,
        "PAYOUT_DRAFT_CREATED",
        {
          id: result.rows[0].id,
          amount_usdt: v.amount_usdt,
          wallet_id: v.wallet_id,
        }
      );

      return ok({
        success: true,
        notice: "Draft only. No funds transferred.",
      }, 201);
    }

    // CANCEL PAYOUT DRAFT
    if (route === "payouts/cancel") {
      if (!can(admin, "PAYOUTS")) {
        return bad("Forbidden", 403);
      }

      const v = z.object({
        id: z.number().int().positive(),
      }).parse(body);

      const result = await database.query(
        `UPDATE payout_requests
         SET status='CANCELLED'
         WHERE id=$1 AND status='DRAFT'
         RETURNING id`,
        [v.id]
      );

      if (!result.rowCount) {
        return bad("Draft not found or already cancelled", 404);
      }

      await auditLog(
        admin.id,
        "PAYOUT_DRAFT_CANCELLED",
        v
      );

      return ok({ success: true });
    }

    return bad("Not found", 404);
  } catch (error) {
    return errorResponse(error);
  }
}
