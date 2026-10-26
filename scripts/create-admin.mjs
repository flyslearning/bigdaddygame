
import pg from "pg";
import bcrypt from "bcryptjs";

const { Client } = pg;

const url = process.env.DATABASE_URL;
const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
const password = process.env.ADMIN_PASSWORD;

if (!url || !email || !password || password.length < 12) {
  throw new Error("Missing DATABASE_URL or valid admin credentials");
}

const client = new Client({ connectionString: url });

try {
  await client.connect();

  const exists = await client.query(
    "SELECT id FROM admins WHERE email=$1",
    [email]
  );

  if (exists.rowCount) {
    console.log("Admin already exists; password unchanged.");
  } else {
    const hash = await bcrypt.hash(password, 12);

    await client.query(
      `INSERT INTO admins(email,pass_hash,role,status)
       VALUES($1,$2,'SUPER_ADMIN','ACTIVE')`,
      [email, hash]
    );

    console.log("Super Admin created successfully!");
  }
} finally {
  await client.end();
}
