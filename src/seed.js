import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import { pool } from "./db.js";

const adminName = process.env.SEED_ADMIN_NAME || "SoftSpark Admin";
const adminEmail = (process.env.SEED_ADMIN_EMAIL || "admin@softspark.local").toLowerCase();
const adminPassword = process.env.SEED_ADMIN_PASSWORD || "LocalAdmin123!";

const defaultAccounts = [
  ["1000", "Cash in Hand", "asset", "debit"],
  ["1010", "Bank Account", "asset", "debit"],
  ["1100", "Accounts Receivable", "asset", "debit"],
  ["1150", "GST Input Tax Credit", "asset", "debit"],
  ["1200", "Inventory", "asset", "debit"],
  ["1500", "Furniture and Equipment", "asset", "debit"],
  ["2000", "Accounts Payable", "liability", "credit"],
  ["2100", "GST Payable", "liability", "credit"],
  ["2200", "Loans Payable", "liability", "credit"],
  ["3000", "Owner's Capital", "equity", "credit"],
  ["3100", "Retained Earnings", "equity", "credit"],
  ["4000", "Sales Revenue", "revenue", "credit"],
  ["4100", "Service Revenue", "revenue", "credit"],
  ["5000", "Cost of Goods Sold", "expense", "debit"],
  ["6000", "Rent Expense", "expense", "debit"],
  ["6100", "Salaries Expense", "expense", "debit"],
  ["6200", "Utilities Expense", "expense", "debit"],
  ["6300", "Office Supplies Expense", "expense", "debit"],
  ["6900", "Other Expenses", "expense", "debit"]
];

try {
  const existing = await pool.query("SELECT id FROM users WHERE email = $1", [adminEmail]);
  let userId;
  if (existing.rowCount) {
    userId = existing.rows[0].id;
    console.log(`Seed user already exists: ${adminEmail}`);
  } else {
    userId = randomUUID();
    const hash = await bcrypt.hash(adminPassword, 12);
    await pool.query(
      "INSERT INTO users (id, full_name, email, password_hash) VALUES ($1,$2,$3,$4)",
      [userId, adminName, adminEmail, hash]
    );
    console.log(`Created development user: ${adminEmail}`);
  }

  const member = await pool.query("SELECT organization_id FROM memberships WHERE user_id = $1 LIMIT 1", [userId]);
  let organizationId;
  let companyId;

  if (member.rowCount) {
    organizationId = member.rows[0].organization_id;
    const c = await pool.query("SELECT id FROM companies WHERE organization_id = $1 ORDER BY created_at LIMIT 1", [organizationId]);
    if (c.rowCount) companyId = c.rows[0].id;
  }

  if (!organizationId) {
    organizationId = randomUUID();
    await pool.query("INSERT INTO organizations (id, name) VALUES ($1,$2)", [organizationId, "SoftSpark Demo Organization"]);
    await pool.query("INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,'owner')", [organizationId, userId]);
  }

  if (!companyId) {
    companyId = randomUUID();
    await pool.query(
      "INSERT INTO companies (id, organization_id, legal_name, trade_name, base_currency, country_code, state_name) VALUES ($1,$2,$3,$4,'INR','IN','Gujarat')",
      [companyId, organizationId, "SoftSpark Demo Company", "AutoBooks Demo"]
    );
  }

  const fy = await pool.query("SELECT id FROM financial_years WHERE company_id = $1 LIMIT 1", [companyId]);
  if (!fy.rowCount) {
    const now = new Date();
    const year = now.getFullYear();
    const startYear = now.getMonth() >= 3 ? year : year - 1;
    const start = `${startYear}-04-01`;
    const end = `${startYear + 1}-03-31`;
    await pool.query(
      "INSERT INTO financial_years (id,company_id,name,start_date,end_date,status) VALUES ($1,$2,$3,$4,$5,'open')",
      [randomUUID(), companyId, `FY ${startYear}-${String(startYear + 1).slice(-2)}`, start, end]
    );
  }

  for (const [code, name, type, normal] of defaultAccounts) {
    await pool.query(
      `INSERT INTO accounts (id, company_id, code, name, account_type, normal_balance, is_system)
       VALUES ($1,$2,$3,$4,$5,$6,TRUE)
       ON CONFLICT (company_id, code) DO NOTHING`,
      [randomUUID(), companyId, code, name, type, normal]
    );
  }

  console.log("Seed completed. Demo organization, company, financial year and default accounts are ready.");
  console.log(`Login email: ${adminEmail}`);
  console.log("Use the password configured in backend/.env.");
} catch (err) {
  console.error("Seed failed:", err.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
