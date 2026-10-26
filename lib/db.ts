
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import fs from "node:fs";
import path from "node:path";

type DB = Database.Database;

const globalDb = globalThis as unknown as {
  __bdDb?: DB;
};

// Get SQLite database
export function db(): DB {
  if (globalDb.__bdDb) {
    return globalDb.__bdDb;
  }

  const filename = path.resolve(
    process.env.DATABASE_PATH ||
      "./data/bigdaddy.sqlite"
  );

  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password || password.length < 12) {
    throw new Error(
      "Set ADMIN_EMAIL and a strong ADMIN_PASSWORD (12+ characters) in your .env file."
    );
  }

  // Create database directory
  fs.mkdirSync(path.dirname(filename), {
    recursive: true,
  });

  const database = new Database(filename);

  try {
    database.pragma("journal_mode = WAL");
    database.pragma("foreign_keys = ON");
    database.pragma("busy_timeout = 5000");

    // Create database tables
    database.exec(`
      CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        pass_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'SUPER_ADMIN',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS players (
        id INTEGER PRIMARY KEY,
        game_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        points INTEGER NOT NULL DEFAULT 0
          CHECK(points >= 0),
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY,
        slug TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'Arcade',
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS points_ledger (
        id INTEGER PRIMARY KEY,
        player_id INTEGER NOT NULL
          REFERENCES players(id),
        delta INTEGER NOT NULL,
        balance_after INTEGER NOT NULL,
        reason TEXT NOT NULL,
        admin_id INTEGER NOT NULL
          REFERENCES admins(id),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY,
        entry_type TEXT NOT NULL
          CHECK(entry_type IN (
            'REVENUE',
            'EXPENSE',
            'DEPOSIT',
            'REFUND'
          )),
        amount_cents INTEGER NOT NULL
          CHECK(amount_cents > 0),
        memo TEXT NOT NULL,
        reference TEXT,
        admin_id INTEGER REFERENCES admins(id),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS wallet_addresses (
        id INTEGER PRIMARY KEY,
        label TEXT NOT NULL,
        network TEXT NOT NULL
          CHECK(network IN ('ERC20', 'TRC20')),
        address TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        admin_id INTEGER NOT NULL
          REFERENCES admins(id),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS payout_requests (
        id INTEGER PRIMARY KEY,
        amount_usdt TEXT NOT NULL,
        wallet_id INTEGER NOT NULL
          REFERENCES wallet_addresses(id),
        status TEXT NOT NULL DEFAULT 'DRAFT'
          CHECK(status IN ('DRAFT', 'CANCELLED')),
        note TEXT,
        admin_id INTEGER NOT NULL
          REFERENCES admins(id),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY,
        admin_id INTEGER REFERENCES admins(id),
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_players_game_id
        ON players(game_id);

      CREATE INDEX IF NOT EXISTS idx_points_player
        ON points_ledger(player_id);

      CREATE INDEX IF NOT EXISTS idx_entries_type
        ON entries(entry_type);

      CREATE INDEX IF NOT EXISTS idx_audit_admin
        ON audit_logs(admin_id);

      CREATE INDEX IF NOT EXISTS idx_payout_wallet
        ON payout_requests(wallet_id);
    `);

    // Create initial admin only when no admins exist
    const count = database
      .prepare("SELECT COUNT(*) AS total FROM admins")
      .get() as { total: number };

    if (count.total === 0) {
      const passwordHash = bcrypt.hashSync(password, 12);

      database
        .prepare(
          `INSERT INTO admins (email, pass_hash, role)
           VALUES (?, ?, ?)`
        )
        .run(email, passwordHash, "SUPER_ADMIN");

      console.log(
        "[BigDaddy GAME] Initial admin created successfully."
      );
    }

    globalDb.__bdDb = database;

    return database;
  } catch (error) {
    database.close();
    throw error;
  }
}

// Save administrator activity
export function log(
  adminId: number,
  action: string,
  details: Record<string, unknown>
): void {
  db()
    .prepare(
      `INSERT INTO audit_logs
       (admin_id, action, details)
       VALUES (?, ?, ?)`
    )
    .run(adminId, action, JSON.stringify(details));
}
