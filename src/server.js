import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { pool } from "./db.js";
import { requireAuth, requireRole } from "./middleware.js";

dotenv.config();
const app = express();
const port = Number(process.env.PORT || 5000);
const jwtSecret = process.env.JWT_SECRET || "";

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "http://localhost:5173",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "1mb" }));

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected", service: "SoftSpark AutoBooks API" });
  } catch {
    res.status(503).json({ status: "error", database: "unavailable" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const schema = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(200) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter a valid email and password." });
  if (jwtSecret.length < 32) return res.status(500).json({ error: "Configure a JWT_SECRET of at least 32 characters in backend/.env." });

  try {
    const email = parsed.data.email.toLowerCase();
    const result = await pool.query("SELECT id, full_name, email, password_hash, status FROM users WHERE email = $1", [email]);
    if (!result.rowCount || result.rows[0].status !== "active") return res.status(401).json({ error: "Invalid email or password." });
    const user = result.rows[0];
    const valid = await bcrypt.compare(parsed.data.password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid email or password." });
    const membership = await pool.query(
      "SELECT organization_id, role FROM memberships WHERE user_id = $1 ORDER BY created_at LIMIT 1",
      [user.id]
    );
    if (!membership.rowCount) return res.status(403).json({ error: "No organization membership found." });
    const token = jwt.sign({ sub: user.id }, jwtSecret, { expiresIn: "8h", issuer: "softspark-autobooks" });
    res.json({
      token,
      user: { id: user.id, fullName: user.full_name, email: user.email, role: membership.rows[0].role, organizationId: membership.rows[0].organization_id }
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed due to a server error." });
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, fullName: req.user.full_name, email: req.user.email, role: req.user.role, organizationId: req.user.organization_id } });
});

app.get("/api/organization", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT id, name, status, created_at FROM organizations WHERE id = $1",
      [req.user.organization_id]
    );
    if (!r.rowCount) return res.status(404).json({ error: "Organization not found." });
    res.json({ organization: r.rows[0] });
  } catch {
    res.status(500).json({ error: "Could not load organization." });
  }
});

app.get("/api/company", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT c.id, c.legal_name, c.trade_name, c.base_currency, c.country_code, c.state_name, c.gstin
       FROM companies c WHERE c.organization_id = $1 ORDER BY c.created_at LIMIT 1`,
      [req.user.organization_id]
    );
    res.json({ company: r.rows[0] || null });
  } catch {
    res.status(500).json({ error: "Could not load company." });
  }
});

app.get("/api/financial-years", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT fy.id, fy.name, fy.start_date, fy.end_date, fy.status
       FROM financial_years fy
       JOIN companies c ON c.id = fy.company_id
       WHERE c.organization_id = $1
       ORDER BY fy.start_date DESC`,
      [req.user.organization_id]
    );
    res.json({ financialYears: r.rows });
  } catch {
    res.status(500).json({ error: "Could not load financial years." });
  }
});

app.get("/api/accounts", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT a.id, a.code, a.name, a.account_type, a.normal_balance, a.is_system, a.is_active
       FROM accounts a JOIN companies c ON c.id = a.company_id
       WHERE c.organization_id = $1
       ORDER BY a.code`,
      [req.user.organization_id]
    );
    res.json({ accounts: r.rows });
  } catch {
    res.status(500).json({ error: "Could not load accounts." });
  }
});

app.post("/api/accounts", requireAuth, requireRole("owner", "admin", "accountant"), async (req, res) => {
  const schema = z.object({
    code: z.string().trim().min(1).max(30),
    name: z.string().trim().min(2).max(160),
    accountType: z.enum(["asset", "liability", "equity", "revenue", "expense"])
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter an account code, name and valid account type." });

  const normalBalance = ["asset", "expense"].includes(parsed.data.accountType) ? "debit" : "credit";
  try {
    const company = await pool.query(
      "SELECT id FROM companies WHERE organization_id = $1 ORDER BY created_at LIMIT 1",
      [req.user.organization_id]
    );
    if (!company.rowCount) return res.status(400).json({ error: "Set up a company before creating accounts." });
    const account = {
      id: randomUUID(), companyId: company.rows[0].id, ...parsed.data, normalBalance
    };
    const r = await pool.query(
      `INSERT INTO accounts (id, company_id, code, name, account_type, normal_balance, is_system)
       VALUES ($1,$2,$3,$4,$5,$6,FALSE)
       RETURNING id, code, name, account_type, normal_balance, is_system, is_active`,
      [account.id, account.companyId, account.code, account.name, account.accountType, account.normalBalance]
    );
    res.status(201).json({ account: r.rows[0] });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "That account code already exists for this company." });
    console.error("Create account error:", err.message);
    res.status(500).json({ error: "Could not create account." });
  }
});


// Phase 2: journal posting, ledger, trial balance and audit trail.
async function getCompanyForOrganization(client, organizationId) {
  const result = await client.query(
    "SELECT id FROM companies WHERE organization_id = $1 ORDER BY created_at LIMIT 1",
    [organizationId]
  );
  return result.rows[0]?.id || null;
}


// Phase 3: customer/supplier master, GST-aware sales invoices and receipts.
app.get("/api/parties", requireAuth, async (req, res) => {
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company first." });
    const result = await pool.query(
      `SELECT id, party_type, name, gstin, email, phone, state_name, address, is_active, created_at
       FROM business_parties WHERE company_id=$1 ORDER BY name`, [companyId]);
    res.json({ parties: result.rows });
  } catch (err) { console.error("List parties error:", err.message); res.status(500).json({ error: "Could not load customers and suppliers." }); }
});

app.post("/api/parties", requireAuth, requireRole("owner", "admin", "accountant", "data_entry"), async (req, res) => {
  const schema = z.object({
    partyType: z.enum(["customer", "supplier", "both"]).default("customer"),
    name: z.string().trim().min(2).max(200),
    gstin: z.string().trim().max(15).optional().default(""),
    email: z.string().trim().email().max(254).optional().or(z.literal("")),
    phone: z.string().trim().max(40).optional().default(""),
    stateName: z.string().trim().max(100).optional().default(""),
    address: z.string().trim().max(2000).optional().default("")
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter a valid party name and contact details." });
  const p = parsed.data;
  if (p.gstin && !/^[0-9A-Z]{15}$/.test(p.gstin.toUpperCase())) return res.status(400).json({ error: "GSTIN must contain 15 uppercase letters/numbers." });
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company first." });
    const result = await pool.query(
      `INSERT INTO business_parties (id, company_id, party_type, name, gstin, email, phone, state_name, address, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id, party_type, name, gstin, email, phone, state_name, address, is_active, created_at`,
      [randomUUID(), companyId, p.partyType, p.name, p.gstin ? p.gstin.toUpperCase() : null, p.email || null, p.phone || null, p.stateName || null, p.address || null, req.user.id]);
    res.status(201).json({ party: result.rows[0] });
  } catch (err) { console.error("Create party error:", err.message); res.status(500).json({ error: "Could not create customer/supplier." }); }
});

app.get("/api/sales-invoices", requireAuth, async (req, res) => {
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company first." });
    const result = await pool.query(
      `SELECT si.id, si.invoice_number, si.invoice_date, si.due_date, si.description, si.taxable_amount,
              si.gst_rate, si.cgst_amount, si.sgst_amount, si.igst_amount, si.total_amount,
              si.amount_received, si.status, bp.name AS customer_name
       FROM sales_invoices si JOIN business_parties bp ON bp.id=si.customer_id
       WHERE si.company_id=$1 ORDER BY si.invoice_date DESC, si.created_at DESC LIMIT 500`, [companyId]);
    res.json({ invoices: result.rows });
  } catch (err) { console.error("List sales invoices error:", err.message); res.status(500).json({ error: "Could not load sales invoices." }); }
});

app.post("/api/sales-invoices", requireAuth, requireRole("owner", "admin", "accountant", "data_entry"), async (req, res) => {
  const schema = z.object({
    customerId: z.string().uuid(), invoiceDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional().or(z.literal("")),
    description: z.string().trim().min(3).max(500), taxableAmount: z.coerce.number().finite().positive().max(999999999999),
    gstRate: z.coerce.number().refine(v => [0,5,12,18,28].includes(v), "GST rate must be 0, 5, 12, 18 or 28 percent.")
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Provide a customer, valid invoice date, description, taxable amount and supported GST rate." });
  const d = parsed.data;
  const money = n => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
  const taxable = money(d.taxableAmount);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const companyResult = await client.query("SELECT id, state_name FROM companies WHERE organization_id=$1 ORDER BY created_at LIMIT 1 FOR UPDATE", [req.user.organization_id]);
    if (!companyResult.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Set up a company first." }); }
    const company = companyResult.rows[0];
    const customerResult = await client.query("SELECT id, name, state_name, party_type, is_active FROM business_parties WHERE id=$1 AND company_id=$2 FOR UPDATE", [d.customerId, company.id]);
    if (!customerResult.rowCount || !customerResult.rows[0].is_active || !["customer", "both"].includes(customerResult.rows[0].party_type)) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Select an active customer belonging to this company." }); }
    const fy = await client.query("SELECT id FROM financial_years WHERE company_id=$1 AND $2::date BETWEEN start_date AND end_date AND status='open' FOR UPDATE", [company.id, d.invoiceDate]);
    if (!fy.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Invoice date must fall within an open financial year." }); }
    const acct = await client.query("SELECT id, code FROM accounts WHERE company_id=$1 AND code = ANY($2::varchar[]) AND is_active=TRUE", [company.id, ["1100", "2100", "4000"]]);
    const accountMap = Object.fromEntries(acct.rows.map(a => [a.code, a.id]));
    if (!accountMap["1100"] || !accountMap["2100"] || !accountMap["4000"]) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Required accounts 1100 (Accounts Receivable), 2100 (GST Payable) and 4000 (Sales Revenue) must exist and be active." }); }
    const customerState = (customerResult.rows[0].state_name || "").trim().toLowerCase();
    const companyState = (company.state_name || "").trim().toLowerCase();
    const intraState = !customerState || !companyState || customerState === companyState;
    const tax = money(taxable * d.gstRate / 100);
    const cgst = intraState ? money(tax / 2) : 0;
    const sgst = intraState ? money(tax - cgst) : 0;
    const igst = intraState ? 0 : tax;
    const total = money(taxable + tax);
    const invoiceId = randomUUID();
    const invoiceNumber = `SI-${d.invoiceDate.slice(0,4)}-${Date.now().toString().slice(-8)}`;
    const entryId = randomUUID();
    await client.query(
      `INSERT INTO journal_entries (id, company_id, financial_year_id, entry_date, description, reference, status, total_debit, total_credit, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,'posted',$7,$7,$8)`,
      [entryId, company.id, fy.rows[0].id, d.invoiceDate, `Sales invoice ${invoiceNumber} — ${d.description}`, invoiceNumber, total.toFixed(2), req.user.id]);
    const journalLines = [
      { accountId: accountMap["1100"], description: `Receivable — ${customerResult.rows[0].name}`, debit: total, credit: 0 },
      { accountId: accountMap["4000"], description: d.description, debit: 0, credit: taxable }
    ];
    if (tax > 0) journalLines.push({ accountId: accountMap["2100"], description: intraState ? "Output CGST/SGST" : "Output IGST", debit: 0, credit: tax });
    for (const line of journalLines) await client.query(
      `INSERT INTO journal_lines (id,journal_entry_id,company_id,account_id,line_description,debit,credit) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [randomUUID(), entryId, company.id, line.accountId, line.description, line.debit.toFixed(2), line.credit.toFixed(2)]);
    await client.query(
      `INSERT INTO sales_invoices (id,company_id,financial_year_id,customer_id,invoice_number,invoice_date,due_date,description,taxable_amount,gst_rate,cgst_amount,sgst_amount,igst_amount,total_amount,status,journal_entry_id,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'posted',$15,$16)`,
      [invoiceId, company.id, fy.rows[0].id, d.customerId, invoiceNumber, d.invoiceDate, d.dueDate || null, d.description, taxable.toFixed(2), d.gstRate, cgst.toFixed(2), sgst.toFixed(2), igst.toFixed(2), total.toFixed(2), entryId, req.user.id]);
    await client.query(
      `INSERT INTO audit_logs (id,organization_id,company_id,user_id,action,entity_type,entity_id,details) VALUES ($1,$2,$3,$4,'sales_invoice.posted','sales_invoice',$5,$6::jsonb)`,
      [randomUUID(), req.user.organization_id, company.id, req.user.id, invoiceId, JSON.stringify({ invoiceNumber, total, gstRate: d.gstRate, journalEntryId: entryId })]);
    await client.query("COMMIT");
    res.status(201).json({ invoice: { id: invoiceId, invoice_number: invoiceNumber, invoice_date: d.invoiceDate, customer_name: customerResult.rows[0].name, taxable_amount: taxable.toFixed(2), gst_rate: d.gstRate, cgst_amount: cgst.toFixed(2), sgst_amount: sgst.toFixed(2), igst_amount: igst.toFixed(2), total_amount: total.toFixed(2), amount_received: "0.00", status: "posted" } });
  } catch (err) { await client.query("ROLLBACK").catch(() => {}); console.error("Create sales invoice error:", err.message); res.status(500).json({ error: "Could not create and post sales invoice." }); }
  finally { client.release(); }
});

app.post("/api/sales-invoices/:id/receipts", requireAuth, requireRole("owner", "admin", "accountant", "data_entry"), async (req, res) => {
  const schema = z.object({ receiptDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/), accountId: z.string().uuid(), amount: z.coerce.number().finite().positive().max(999999999999), reference: z.string().trim().max(120).optional().default("") });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Provide a valid receipt date, bank/cash account and amount." });
  const d = parsed.data; const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const company = await client.query("SELECT id FROM companies WHERE organization_id=$1 ORDER BY created_at LIMIT 1", [req.user.organization_id]);
    if (!company.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Set up a company first." }); }
    const companyId = company.rows[0].id;
    const invoice = await client.query("SELECT * FROM sales_invoices WHERE id=$1 AND company_id=$2 FOR UPDATE", [req.params.id, companyId]);
    if (!invoice.rowCount || invoice.rows[0].status === 'cancelled') { await client.query("ROLLBACK"); return res.status(404).json({ error: "Active sales invoice not found." }); }
    const inv = invoice.rows[0]; const amount = Math.round((d.amount + Number.EPSILON) * 100) / 100;
    const due = Number(inv.total_amount) - Number(inv.amount_received);
    if (amount > due + 0.001) { await client.query("ROLLBACK"); return res.status(400).json({ error: `Receipt exceeds the outstanding balance of ₹${due.toFixed(2)}.` }); }
    const fy = await client.query("SELECT id FROM financial_years WHERE company_id=$1 AND $2::date BETWEEN start_date AND end_date AND status='open' FOR UPDATE", [companyId, d.receiptDate]);
    if (!fy.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Receipt date must fall within an open financial year." }); }
    const accounts = await client.query("SELECT id, code, account_type FROM accounts WHERE company_id=$1 AND id=ANY($2::uuid[]) AND is_active=TRUE", [companyId, [d.accountId]]);
    if (!accounts.rowCount || accounts.rows[0].account_type !== "asset") { await client.query("ROLLBACK"); return res.status(400).json({ error: "Select an active asset account (cash or bank) belonging to this company." }); }
    const ar = await client.query("SELECT id FROM accounts WHERE company_id=$1 AND code='1100' AND is_active=TRUE", [companyId]);
    if (!ar.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Accounts Receivable account 1100 is missing." }); }
    const receiptId = randomUUID(); const receiptNumber = `RC-${d.receiptDate.slice(0,4)}-${Date.now().toString().slice(-8)}`; const entryId = randomUUID();
    await client.query(`INSERT INTO journal_entries (id,company_id,financial_year_id,entry_date,description,reference,status,total_debit,total_credit,created_by) VALUES ($1,$2,$3,$4,$5,$6,'posted',$7,$7,$8)`, [entryId, companyId, fy.rows[0].id, d.receiptDate, `Receipt ${receiptNumber} for ${inv.invoice_number}`, d.reference || receiptNumber, amount.toFixed(2), req.user.id]);
    for (const line of [{accountId:d.accountId, description:`Receipt against ${inv.invoice_number}`, debit:amount, credit:0},{accountId:ar.rows[0].id, description:`Receivable settled — ${inv.invoice_number}`, debit:0, credit:amount}]) await client.query(`INSERT INTO journal_lines (id,journal_entry_id,company_id,account_id,line_description,debit,credit) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [randomUUID(),entryId,companyId,line.accountId,line.description,line.debit.toFixed(2),line.credit.toFixed(2)]);
    await client.query(`INSERT INTO sales_receipts (id,company_id,invoice_id,receipt_number,receipt_date,account_id,amount,reference,journal_entry_id,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [receiptId,companyId,inv.id,receiptNumber,d.receiptDate,d.accountId,amount.toFixed(2),d.reference || null,entryId,req.user.id]);
    const received = Math.round((Number(inv.amount_received) + amount + Number.EPSILON) * 100) / 100;
    const status = received >= Number(inv.total_amount) ? 'paid' : 'partially_paid';
    await client.query("UPDATE sales_invoices SET amount_received=$1,status=$2 WHERE id=$3", [received.toFixed(2),status,inv.id]);
    await client.query(`INSERT INTO audit_logs (id,organization_id,company_id,user_id,action,entity_type,entity_id,details) VALUES ($1,$2,$3,$4,'sales_receipt.posted','sales_receipt',$5,$6::jsonb)`, [randomUUID(),req.user.organization_id,companyId,req.user.id,receiptId,JSON.stringify({receiptNumber, invoiceNumber:inv.invoice_number, amount, journalEntryId:entryId})]);
    await client.query("COMMIT"); res.status(201).json({ receipt:{id:receiptId,receipt_number:receiptNumber,amount:amount.toFixed(2),status} });
  } catch(err) { await client.query("ROLLBACK").catch(()=>{}); console.error("Create receipt error:",err.message); res.status(500).json({error:"Could not post receipt."}); }
  finally { client.release(); }
});

// Phase 4: supplier purchase bills and supplier payments.
app.get("/api/purchase-bills", requireAuth, async (req, res) => {
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company first." });
    const result = await pool.query(
      `SELECT pb.id, pb.bill_number, pb.bill_date, pb.due_date, pb.description, pb.taxable_amount,
              pb.gst_rate, pb.cgst_amount, pb.sgst_amount, pb.igst_amount, pb.total_amount,
              pb.amount_paid, pb.status, bp.name AS supplier_name, a.code AS expense_code, a.name AS expense_account_name
       FROM purchase_bills pb JOIN business_parties bp ON bp.id=pb.supplier_id
       JOIN accounts a ON a.id=pb.expense_account_id
       WHERE pb.company_id=$1 ORDER BY pb.bill_date DESC, pb.created_at DESC LIMIT 300`, [companyId]);
    res.json({ purchaseBills: result.rows });
  } catch (err) { console.error("List purchase bills error:", err.message); res.status(500).json({ error: "Could not load purchase bills." }); }
});

app.post("/api/purchase-bills", requireAuth, requireRole("owner", "admin", "accountant", "data_entry"), async (req, res) => {
  const schema = z.object({
    supplierId: z.string().uuid(), billNumber: z.string().trim().max(60).optional().default(""),
    billDate: z.string().regex(/^\d{4}-\\d{2}-\\d{2}$/), dueDate: z.string().regex(/^\d{4}-\\d{2}-\\d{2}$/).optional().or(z.literal("")),
    description: z.string().trim().min(3).max(500), expenseAccountId: z.string().uuid(),
    taxableAmount: z.coerce.number().finite().positive().max(999999999999), gstRate: z.coerce.number().refine(v => [0,5,12,18,28].includes(v))
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter a supplier, bill date, description, expense account, taxable amount and supported GST rate." });
  const d = parsed.data; const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const company = await client.query("SELECT id, state_name FROM companies WHERE organization_id=$1 ORDER BY created_at LIMIT 1", [req.user.organization_id]);
    if (!company.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Set up a company first." }); }
    const companyId = company.rows[0].id;
    const supplier = await client.query("SELECT id,name,state_name FROM business_parties WHERE id=$1 AND company_id=$2 AND party_type IN ('supplier','both') AND is_active=TRUE", [d.supplierId, companyId]);
    if (!supplier.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Select an active supplier belonging to this company." }); }
    const fy = await client.query("SELECT id FROM financial_years WHERE company_id=$1 AND $2::date BETWEEN start_date AND end_date AND status='open' FOR UPDATE", [companyId, d.billDate]);
    if (!fy.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Bill date must fall within an open financial year." }); }
    const expense = await client.query("SELECT id,account_type FROM accounts WHERE id=$1 AND company_id=$2 AND is_active=TRUE", [d.expenseAccountId, companyId]);
    if (!expense.rowCount || expense.rows[0].account_type !== 'expense') { await client.query("ROLLBACK"); return res.status(400).json({ error: "Select an active expense account belonging to this company." }); }
    const acct = await client.query("SELECT id,code FROM accounts WHERE company_id=$1 AND code=ANY($2::varchar[]) AND is_active=TRUE", [companyId, ["2000","1150"]]);
    const accountMap = Object.fromEntries(acct.rows.map(a => [a.code,a.id]));
    if (!accountMap["2000"] || !accountMap["1150"]) { await client.query("ROLLBACK"); return res.status(400).json({ error: "Required accounts 2000 (Accounts Payable) and 1150 (GST Input Tax Credit) must exist and be active. Run npm run seed to add missing defaults." }); }
    const taxable = Math.round((d.taxableAmount + Number.EPSILON)*100)/100;
    const tax = Math.round((taxable*d.gstRate/100 + Number.EPSILON)*100)/100;
    const intraState = !company.rows[0].state_name || !supplier.rows[0].state_name || company.rows[0].state_name.trim().toLowerCase() === supplier.rows[0].state_name.trim().toLowerCase();
    const cgst = tax && intraState ? Math.round((tax/2 + Number.EPSILON)*100)/100 : 0;
    const sgst = tax && intraState ? Math.round((tax-cgst + Number.EPSILON)*100)/100 : 0;
    const igst = tax && !intraState ? tax : 0;
    const total = Math.round((taxable+tax+Number.EPSILON)*100)/100;
    const billId = randomUUID();
    const billNumber = d.billNumber || `PB-${d.billDate.slice(0,4)}-${Date.now().toString().slice(-8)}`;
    const entryId = randomUUID();
    await client.query(`INSERT INTO journal_entries (id,company_id,financial_year_id,entry_date,description,reference,status,total_debit,total_credit,created_by) VALUES ($1,$2,$3,$4,$5,$6,'posted',$7,$7,$8)`, [entryId,companyId,fy.rows[0].id,d.billDate,`Purchase bill ${billNumber} — ${d.description}`,billNumber,total.toFixed(2),req.user.id]);
    const lines = [{accountId:d.expenseAccountId,description:d.description,debit:taxable,credit:0}];
    if (tax > 0) lines.push({accountId:accountMap["1150"],description:intraState ? "Input CGST/SGST credit" : "Input IGST credit",debit:tax,credit:0});
    lines.push({accountId:accountMap["2000"],description:`Payable — ${supplier.rows[0].name}`,debit:0,credit:total});
    for (const line of lines) await client.query(`INSERT INTO journal_lines (id,journal_entry_id,company_id,account_id,line_description,debit,credit) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [randomUUID(),entryId,companyId,line.accountId,line.description,line.debit.toFixed(2),line.credit.toFixed(2)]);
    await client.query(`INSERT INTO purchase_bills (id,company_id,financial_year_id,supplier_id,bill_number,bill_date,due_date,description,expense_account_id,taxable_amount,gst_rate,cgst_amount,sgst_amount,igst_amount,total_amount,status,journal_entry_id,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'posted',$16,$17)`, [billId,companyId,fy.rows[0].id,d.supplierId,billNumber,d.billDate,d.dueDate||null,d.description,d.expenseAccountId,taxable.toFixed(2),d.gstRate,cgst.toFixed(2),sgst.toFixed(2),igst.toFixed(2),total.toFixed(2),entryId,req.user.id]);
    await client.query(`INSERT INTO audit_logs (id,organization_id,company_id,user_id,action,entity_type,entity_id,details) VALUES ($1,$2,$3,$4,'purchase_bill.posted','purchase_bill',$5,$6::jsonb)`, [randomUUID(),req.user.organization_id,companyId,req.user.id,billId,JSON.stringify({billNumber,total,gstRate:d.gstRate,journalEntryId:entryId})]);
    await client.query("COMMIT");
    res.status(201).json({ purchaseBill:{id:billId,bill_number:billNumber,bill_date:d.billDate,supplier_name:supplier.rows[0].name,taxable_amount:taxable.toFixed(2),gst_rate:d.gstRate,cgst_amount:cgst.toFixed(2),sgst_amount:sgst.toFixed(2),igst_amount:igst.toFixed(2),total_amount:total.toFixed(2),amount_paid:"0.00",status:"posted"} });
  } catch(err) { await client.query("ROLLBACK").catch(()=>{}); if (err.code === "23505") return res.status(409).json({error:"That supplier bill number already exists for this company."}); console.error("Create purchase bill error:",err.message); res.status(500).json({error:"Could not create and post purchase bill."}); }
  finally { client.release(); }
});

app.post("/api/purchase-bills/:id/payments", requireAuth, requireRole("owner", "admin", "accountant", "data_entry"), async (req, res) => {
  const schema = z.object({ paymentDate: z.string().regex(/^\d{4}-\\d{2}-\\d{2}$/), accountId: z.string().uuid(), amount: z.coerce.number().finite().positive().max(999999999999), reference: z.string().trim().max(120).optional().default("") });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Provide a valid payment date, cash/bank account and amount."});
  const d=parsed.data; const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const company=await client.query("SELECT id FROM companies WHERE organization_id=$1 ORDER BY created_at LIMIT 1",[req.user.organization_id]);
    if(!company.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"Set up a company first."});}
    const companyId=company.rows[0].id;
    const bill=await client.query("SELECT * FROM purchase_bills WHERE id=$1 AND company_id=$2 FOR UPDATE",[req.params.id,companyId]);
    if(!bill.rowCount || bill.rows[0].status==='cancelled'){await client.query("ROLLBACK");return res.status(404).json({error:"Active purchase bill not found."});}
    const b=bill.rows[0], amount=Math.round((d.amount+Number.EPSILON)*100)/100, due=Number(b.total_amount)-Number(b.amount_paid);
    if(amount>due+0.001){await client.query("ROLLBACK");return res.status(400).json({error:`Payment exceeds outstanding balance of ₹${due.toFixed(2)}.`});}
    const fy=await client.query("SELECT id FROM financial_years WHERE company_id=$1 AND $2::date BETWEEN start_date AND end_date AND status='open' FOR UPDATE",[companyId,d.paymentDate]);
    if(!fy.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"Payment date must fall within an open financial year."});}
    const bank=await client.query("SELECT id,account_type FROM accounts WHERE id=$1 AND company_id=$2 AND is_active=TRUE",[d.accountId,companyId]);
    if(!bank.rowCount||bank.rows[0].account_type!=='asset'){await client.query("ROLLBACK");return res.status(400).json({error:"Select an active cash/bank asset account belonging to this company."});}
    const ap=await client.query("SELECT id FROM accounts WHERE company_id=$1 AND code='2000' AND is_active=TRUE",[companyId]);
    if(!ap.rowCount){await client.query("ROLLBACK");return res.status(400).json({error:"Accounts Payable account 2000 is missing."});}
    const paymentId=randomUUID(), paymentNumber=`SP-${d.paymentDate.slice(0,4)}-${Date.now().toString().slice(-8)}`, entryId=randomUUID();
    await client.query(`INSERT INTO journal_entries (id,company_id,financial_year_id,entry_date,description,reference,status,total_debit,total_credit,created_by) VALUES ($1,$2,$3,$4,$5,$6,'posted',$7,$7,$8)`,[entryId,companyId,fy.rows[0].id,d.paymentDate,`Supplier payment ${paymentNumber} for ${b.bill_number}`,d.reference||paymentNumber,amount.toFixed(2),req.user.id]);
    for(const line of [{accountId:ap.rows[0].id,description:`Payable settled — ${b.bill_number}`,debit:amount,credit:0},{accountId:d.accountId,description:`Supplier payment — ${b.bill_number}`,debit:0,credit:amount}]) await client.query(`INSERT INTO journal_lines (id,journal_entry_id,company_id,account_id,line_description,debit,credit) VALUES ($1,$2,$3,$4,$5,$6,$7)`,[randomUUID(),entryId,companyId,line.accountId,line.description,line.debit.toFixed(2),line.credit.toFixed(2)]);
    await client.query(`INSERT INTO supplier_payments (id,company_id,bill_id,payment_number,payment_date,account_id,amount,reference,journal_entry_id,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[paymentId,companyId,b.id,paymentNumber,d.paymentDate,d.accountId,amount.toFixed(2),d.reference||null,entryId,req.user.id]);
    const paid=Math.round((Number(b.amount_paid)+amount+Number.EPSILON)*100)/100, status=paid>=Number(b.total_amount)?'paid':'partially_paid';
    await client.query("UPDATE purchase_bills SET amount_paid=$1,status=$2 WHERE id=$3",[paid.toFixed(2),status,b.id]);
    await client.query(`INSERT INTO audit_logs (id,organization_id,company_id,user_id,action,entity_type,entity_id,details) VALUES ($1,$2,$3,$4,'supplier_payment.posted','supplier_payment',$5,$6::jsonb)`,[randomUUID(),req.user.organization_id,companyId,req.user.id,paymentId,JSON.stringify({paymentNumber,billNumber:b.bill_number,amount,journalEntryId:entryId})]);
    await client.query("COMMIT"); res.status(201).json({payment:{id:paymentId,payment_number:paymentNumber,amount:amount.toFixed(2),status}});
  } catch(err){await client.query("ROLLBACK").catch(()=>{});console.error("Supplier payment error:",err.message);res.status(500).json({error:"Could not post supplier payment."});}
  finally{client.release();}
});

app.get("/api/journals", requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT je.id, je.entry_number, je.entry_date, je.description, je.reference,
              je.status, je.total_debit, je.total_credit, je.created_at,
              u.full_name AS created_by_name
       FROM journal_entries je
       JOIN companies c ON c.id = je.company_id
       JOIN users u ON u.id = je.created_by
       WHERE c.organization_id = $1
       ORDER BY je.entry_date DESC, je.entry_number DESC LIMIT 500`,
      [req.user.organization_id]
    );
    res.json({ journals: r.rows });
  } catch (err) {
    console.error("List journals error:", err.message);
    res.status(500).json({ error: "Could not load journal entries." });
  }
});

app.post("/api/journals", requireAuth, requireRole("owner", "admin", "accountant", "data_entry"), async (req, res) => {
  const schema = z.object({
    entryDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    description: z.string().trim().min(3).max(500),
    reference: z.string().trim().max(120).optional().default(""),
    lines: z.array(z.object({
      accountId: z.string().uuid(),
      description: z.string().trim().max(300).optional().default(""),
      debit: z.coerce.number().finite().min(0).max(9999999999999999),
      credit: z.coerce.number().finite().min(0).max(9999999999999999)
    })).min(2).max(100)
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Provide a valid date, description and at least two journal lines." });
  const { entryDate, description, reference, lines } = parsed.data;
  const cents = n => Math.round((n + Number.EPSILON) * 100);
  if (lines.some(l => (l.debit > 0) === (l.credit > 0))) {
    return res.status(400).json({ error: "Each line must contain either a positive debit or a positive credit, not both." });
  }
  const debitCents = lines.reduce((sum, l) => sum + cents(l.debit), 0);
  const creditCents = lines.reduce((sum, l) => sum + cents(l.credit), 0);
  if (debitCents <= 0 || debitCents !== creditCents) {
    return res.status(400).json({ error: "Journal is not balanced. Total debits must equal total credits and be greater than zero." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const companyId = await getCompanyForOrganization(client, req.user.organization_id);
    if (!companyId) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Set up a company before posting journals." });
    }
    const fyResult = await client.query(
      `SELECT id, status FROM financial_years
       WHERE company_id = $1 AND $2::date BETWEEN start_date AND end_date
       FOR UPDATE`, [companyId, entryDate]
    );
    if (!fyResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "The journal date must fall within a configured financial year." });
    }
    if (fyResult.rows[0].status !== "open") {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This financial year is closed. Journals cannot be posted to it." });
    }
    const accountIds = [...new Set(lines.map(l => l.accountId))];
    const accountResult = await client.query(
      `SELECT id, is_active FROM accounts WHERE company_id = $1 AND id = ANY($2::uuid[])`,
      [companyId, accountIds]
    );
    if (accountResult.rowCount !== accountIds.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "One or more accounts do not belong to this company." });
    }
    if (accountResult.rows.some(a => !a.is_active)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Inactive accounts cannot be used in a journal." });
    }
    const entryId = randomUUID();
    const debit = (debitCents / 100).toFixed(2);
    const credit = (creditCents / 100).toFixed(2);
    const entryResult = await client.query(
      `INSERT INTO journal_entries
       (id, company_id, financial_year_id, entry_date, description, reference, status, total_debit, total_credit, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,'posted',$7,$8,$9)
       RETURNING id, entry_number, entry_date, description, reference, status, total_debit, total_credit, created_at`,
      [entryId, companyId, fyResult.rows[0].id, entryDate, description, reference || null, debit, credit, req.user.id]
    );
    for (const line of lines) {
      await client.query(
        `INSERT INTO journal_lines (id, journal_entry_id, company_id, account_id, line_description, debit, credit)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [randomUUID(), entryId, companyId, line.accountId, line.description || null, line.debit.toFixed(2), line.credit.toFixed(2)]
      );
    }
    await client.query(
      `INSERT INTO audit_logs (id, organization_id, company_id, user_id, action, entity_type, entity_id, details)
       VALUES ($1,$2,$3,$4,'journal.posted','journal_entry',$5,$6::jsonb)`,
      [randomUUID(), req.user.organization_id, companyId, req.user.id, entryId,
       JSON.stringify({ entryNumber: entryResult.rows[0].entry_number, entryDate, description, totalDebit: debit, totalCredit: credit, lineCount: lines.length })]
    );
    await client.query("COMMIT");
    res.status(201).json({ journal: entryResult.rows[0] });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Post journal error:", err.message);
    res.status(500).json({ error: "Could not post journal entry." });
  } finally {
    client.release();
  }
});

app.get("/api/journals/:id/lines", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT jl.id, jl.account_id, a.code AS account_code, a.name AS account_name,
              jl.line_description, jl.debit, jl.credit
       FROM journal_lines jl JOIN accounts a ON a.id = jl.account_id
       JOIN journal_entries je ON je.id = jl.journal_entry_id
       JOIN companies c ON c.id = je.company_id
       WHERE je.id = $1 AND c.organization_id = $2 ORDER BY a.code`,
      [req.params.id, req.user.organization_id]
    );
    if (!result.rowCount) {
      const exists = await pool.query(
        `SELECT 1 FROM journal_entries je JOIN companies c ON c.id=je.company_id WHERE je.id=$1 AND c.organization_id=$2`,
        [req.params.id, req.user.organization_id]
      );
      if (!exists.rowCount) return res.status(404).json({ error: "Journal entry not found." });
    }
    res.json({ lines: result.rows });
  } catch (err) {
    console.error("Journal lines error:", err.message);
    res.status(500).json({ error: "Could not load journal lines." });
  }
});

app.get("/api/reports/trial-balance", requireAuth, async (req, res) => {
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company first." });
    const yearId = String(req.query.financialYearId || "");
    const fy = await pool.query(
      "SELECT id, name, start_date, end_date, status FROM financial_years WHERE company_id=$1 AND ($2='' OR id::text=$2) ORDER BY start_date DESC LIMIT 1",
      [companyId, yearId]
    );
    if (!fy.rowCount) return res.json({ financialYear: null, rows: [], totals: { debit: "0.00", credit: "0.00" } });
    const result = await pool.query(
      `SELECT a.id, a.code, a.name, a.account_type, a.normal_balance,
              COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.debit ELSE 0 END),0)::numeric(18,2) AS total_debit,
              COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.credit ELSE 0 END),0)::numeric(18,2) AS total_credit
       FROM accounts a
       LEFT JOIN journal_lines jl ON jl.account_id=a.id AND jl.company_id=a.company_id
       LEFT JOIN journal_entries je ON je.id=jl.journal_entry_id AND je.status='posted'
         AND je.financial_year_id=$2 AND je.entry_date BETWEEN $3::date AND $4::date
       WHERE a.company_id=$1 AND a.is_active=TRUE
       GROUP BY a.id, a.code, a.name, a.account_type, a.normal_balance
       ORDER BY a.code`,
      [companyId, fy.rows[0].id, fy.rows[0].start_date, fy.rows[0].end_date]
    );
    const rows = result.rows.map(r => {
      const debit = Number(r.total_debit); const credit = Number(r.total_credit);
      const balance = r.normal_balance === "debit" ? debit - credit : credit - debit;
      return { ...r, balance: Math.abs(balance).toFixed(2), balance_side: balance >= 0 ? r.normal_balance : (r.normal_balance === "debit" ? "credit" : "debit") };
    });
    const totals = rows.reduce((a, r) => ({ debit: a.debit + Number(r.total_debit), credit: a.credit + Number(r.total_credit) }), { debit: 0, credit: 0 });
    res.json({ financialYear: fy.rows[0], rows, totals: { debit: totals.debit.toFixed(2), credit: totals.credit.toFixed(2) } });
  } catch (err) {
    console.error("Trial balance error:", err.message);
    res.status(500).json({ error: "Could not calculate trial balance." });
  }
});

app.get("/api/reports/financial-statements", requireAuth, async (req, res) => {
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company first." });
    const yearId = String(req.query.financialYearId || "");
    const fy = await pool.query(
      "SELECT id, name, start_date, end_date, status FROM financial_years WHERE company_id=$1 AND ($2='' OR id::text=$2) ORDER BY start_date DESC LIMIT 1",
      [companyId, yearId]
    );
    if (!fy.rowCount) return res.json({ financialYear: null, incomeStatement: [], balanceSheet: [], gstSummary: { salesTaxable: "0.00", outputCgst: "0.00", outputSgst: "0.00", outputIgst: "0.00", purchaseTaxable: "0.00", inputCgst: "0.00", inputSgst: "0.00", inputIgst: "0.00", netGstPayable: "0.00" } });
    const year = fy.rows[0];
    const movements = await pool.query(
      `SELECT a.id,a.code,a.name,a.account_type,a.normal_balance,
        COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.debit ELSE 0 END),0)::numeric(18,2) AS debit,
        COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.credit ELSE 0 END),0)::numeric(18,2) AS credit
       FROM accounts a
       LEFT JOIN journal_lines jl ON jl.account_id=a.id AND jl.company_id=a.company_id
       LEFT JOIN journal_entries je ON je.id=jl.journal_entry_id AND je.status='posted'
         AND je.entry_date BETWEEN $2::date AND $3::date
       WHERE a.company_id=$1 AND a.is_active=TRUE
       GROUP BY a.id,a.code,a.name,a.account_type,a.normal_balance ORDER BY a.code`,
      [companyId, year.start_date, year.end_date]
    );
    const accountRows = movements.rows.map(r => {
      const debit=Number(r.debit), credit=Number(r.credit);
      const signed = r.normal_balance === "debit" ? debit-credit : credit-debit;
      return {...r, debit:debit.toFixed(2), credit:credit.toFixed(2), balance:Math.abs(signed).toFixed(2), balance_side:signed>=0?r.normal_balance:(r.normal_balance==="debit"?"credit":"debit")};
    });
    const incomeStatement = accountRows.filter(r => ["revenue","expense"].includes(r.account_type) && Number(r.debit)+Number(r.credit)>0).map(r=>({code:r.code,name:r.name,type:r.account_type,amount:r.account_type==="revenue"?Number(r.credit)-Number(r.debit):Number(r.debit)-Number(r.credit)}));
    const balanceSheet = accountRows.filter(r => ["asset","liability","equity"].includes(r.account_type) && Number(r.balance)>0).map(r=>({code:r.code,name:r.name,type:r.account_type,balance:Number(r.balance),side:r.balance_side}));
    const incomeTotals = incomeStatement.reduce((a,r)=>{if(r.type==="revenue")a.revenue+=r.amount;else a.expenses+=r.amount;return a;},{revenue:0,expenses:0});
    const gst = await pool.query(
      `SELECT
        COALESCE((SELECT SUM(taxable_amount) FROM sales_invoices WHERE company_id=$1 AND status<>'cancelled' AND invoice_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS sales_taxable,
        COALESCE((SELECT SUM(cgst_amount) FROM sales_invoices WHERE company_id=$1 AND status<>'cancelled' AND invoice_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS output_cgst,
        COALESCE((SELECT SUM(sgst_amount) FROM sales_invoices WHERE company_id=$1 AND status<>'cancelled' AND invoice_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS output_sgst,
        COALESCE((SELECT SUM(igst_amount) FROM sales_invoices WHERE company_id=$1 AND status<>'cancelled' AND invoice_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS output_igst,
        COALESCE((SELECT SUM(taxable_amount) FROM purchase_bills WHERE company_id=$1 AND status<>'cancelled' AND bill_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS purchase_taxable,
        COALESCE((SELECT SUM(cgst_amount) FROM purchase_bills WHERE company_id=$1 AND status<>'cancelled' AND bill_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS input_cgst,
        COALESCE((SELECT SUM(sgst_amount) FROM purchase_bills WHERE company_id=$1 AND status<>'cancelled' AND bill_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS input_sgst,
        COALESCE((SELECT SUM(igst_amount) FROM purchase_bills WHERE company_id=$1 AND status<>'cancelled' AND bill_date BETWEEN $2::date AND $3::date),0)::numeric(18,2) AS input_igst`,
      [companyId, year.start_date, year.end_date]
    );
    const g=gst.rows[0];
    const output=Number(g.output_cgst)+Number(g.output_sgst)+Number(g.output_igst);
    const input=Number(g.input_cgst)+Number(g.input_sgst)+Number(g.input_igst);
    res.json({ financialYear:year, incomeStatement, incomeTotals:{revenue:incomeTotals.revenue.toFixed(2),expenses:incomeTotals.expenses.toFixed(2),netProfit:(incomeTotals.revenue-incomeTotals.expenses).toFixed(2)}, balanceSheet, gstSummary:{salesTaxable:g.sales_taxable,outputCgst:g.output_cgst,outputSgst:g.output_sgst,outputIgst:g.output_igst,purchaseTaxable:g.purchase_taxable,inputCgst:g.input_cgst,inputSgst:g.input_sgst,inputIgst:g.input_igst,netGstPayable:(output-input).toFixed(2)} });
  } catch (err) {
    console.error("Financial reports error:", err.message);
    res.status(500).json({ error: "Could not calculate financial reports." });
  }
});

app.get("/api/ledger/:accountId", requireAuth, async (req, res) => {
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company first." });
    const account = await pool.query("SELECT id, code, name, normal_balance FROM accounts WHERE id=$1 AND company_id=$2", [req.params.accountId, companyId]);
    if (!account.rowCount) return res.status(404).json({ error: "Account not found." });
    const result = await pool.query(
      `SELECT je.id AS journal_id, je.entry_number, je.entry_date, je.description,
              jl.line_description, jl.debit, jl.credit
       FROM journal_lines jl JOIN journal_entries je ON je.id=jl.journal_entry_id
       WHERE jl.account_id=$1 AND jl.company_id=$2 AND je.status='posted'
       ORDER BY je.entry_date, je.entry_number`, [req.params.accountId, companyId]
    );
    let running = 0;
    const lines = result.rows.map(r => {
      running += account.rows[0].normal_balance === "debit" ? Number(r.debit) - Number(r.credit) : Number(r.credit) - Number(r.debit);
      return { ...r, running_balance: Math.abs(running).toFixed(2), balance_side: running >= 0 ? account.rows[0].normal_balance : (account.rows[0].normal_balance === "debit" ? "credit" : "debit") };
    });
    res.json({ account: account.rows[0], lines });
  } catch (err) {
    console.error("Ledger error:", err.message);
    res.status(500).json({ error: "Could not load account ledger." });
  }
});

app.get("/api/ai/insights", requireAuth, async (req, res) => {
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company before generating insights." });
    const [sales, purchases, receivables, payables, balances] = await Promise.all([
      pool.query("SELECT COALESCE(SUM(total_amount),0)::numeric(18,2) AS total FROM sales_invoices WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query("SELECT COALESCE(SUM(total_amount),0)::numeric(18,2) AS total FROM purchase_bills WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query("SELECT COALESCE(SUM(GREATEST(total_amount-amount_received,0)),0)::numeric(18,2) AS total FROM sales_invoices WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query("SELECT COALESCE(SUM(GREATEST(total_amount-amount_paid,0)),0)::numeric(18,2) AS total FROM purchase_bills WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query(`SELECT a.code,a.name,a.account_type,COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.debit ELSE 0 END),0)::numeric(18,2) AS debit,COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.credit ELSE 0 END),0)::numeric(18,2) AS credit
        FROM accounts a LEFT JOIN journal_lines jl ON jl.account_id=a.id AND jl.company_id=a.company_id
        LEFT JOIN journal_entries je ON je.id=jl.journal_entry_id AND je.status='posted'
        WHERE a.company_id=$1 AND a.is_active=TRUE GROUP BY a.code,a.name,a.account_type ORDER BY a.code LIMIT 60`, [companyId])
    ]);
    const metrics = { sales:Number(sales.rows[0].total), purchases:Number(purchases.rows[0].total), receivables:Number(receivables.rows[0].total), payables:Number(payables.rows[0].total) };
    const context = { metrics, accountSummary: balances.rows.map(r=>({code:r.code,name:r.name,type:r.account_type,debit:Number(r.debit),credit:Number(r.credit)})) };
    let insights = [];
    let engine = "Local accounting rules (no AI API key configured)";
    if (process.env.GROQ_API_KEY) {
      try {
        const { default: Groq } = await import("groq-sdk");
        const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
        const model = process.env.GROQ_MODEL || "openai/gpt-oss-120b";
        const completion = await groq.chat.completions.create({
          model,
          messages: [
            { role: "system", content: "You are an accounting analysis assistant for Indian small businesses. Use only the provided figures. Do not invent transactions, tax advice, or causes. Give 3 to 6 concise actionable insights. Return valid JSON only in this schema: {\"insights\":[{\"title\":\"...\",\"detail\":\"...\"}]}. Include a note to verify the books before decisions." },
            { role: "user", content: JSON.stringify(context) }
          ],
          temperature: 0.2,
          max_completion_tokens: 2048,
          top_p: 1,
          reasoning_effort: process.env.GROQ_REASONING_EFFORT || "medium",
          stream: false
        });
        const content = completion.choices?.[0]?.message?.content || "";
        const cleaned = content.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
        const parsed = JSON.parse(cleaned);
        if (!Array.isArray(parsed.insights)) throw new Error("Unexpected AI response format");
        insights = parsed.insights.slice(0, 6).map(item => ({
          title: String(item.title || "Financial observation").slice(0, 120),
          detail: String(item.detail || "Review the related accounting records.").slice(0, 1200)
        }));
        engine = `Groq ${model}`;
      } catch (aiErr) {
        console.error("Groq AI insights provider error:", aiErr.message);
        return res.status(502).json({ error: "Groq could not generate insights. Check GROQ_API_KEY, GROQ_MODEL and the backend connection." });
      }
    } else {
      insights.push({ title: metrics.receivables > 0 ? "Review outstanding customer invoices" : "Customer receivables are clear", detail: metrics.receivables > 0 ? `₹${metrics.receivables.toFixed(2)} remains outstanding across recorded sales invoices. Review due dates and follow up with customers.` : "No outstanding customer balance was found in the recorded sales invoices." });
      insights.push({ title: metrics.payables > 0 ? "Plan supplier payments" : "Supplier balances are clear", detail: metrics.payables > 0 ? `₹${metrics.payables.toFixed(2)} remains payable on recorded purchase bills. Check due dates and available cash before scheduling payments.` : "No outstanding supplier balance was found in the recorded purchase bills." });
      insights.push({ title: "Compare recorded sales and purchases", detail: `Recorded invoice totals are ₹${metrics.sales.toFixed(2)} for sales and ₹${metrics.purchases.toFixed(2)} for purchases. These totals are not profit; review expenses, credits and the complete ledger before drawing conclusions.` });
      const unbalanced = context.accountSummary.some(a => Math.abs(a.debit-a.credit) > 0.01);
      insights.push({ title: "Review account movements", detail: unbalanced ? "At least one account has different total debits and credits across its transactions. Review the trial balance and journal entries; account-level differences alone do not necessarily indicate an error." : "No account-level debit/credit difference was detected in the summarized data. Review the trial balance for the selected financial year as well." });
    }
    res.json({ metrics, insights, engine, generatedAt:new Date().toISOString(), note:"Verify source transactions and reports before making financial or compliance decisions." });
  } catch (err) {
    console.error("AI insights error:", err.message);
    res.status(500).json({ error: "Could not generate financial insights." });
  }
});



// Phase 6: read-only natural-language accounting assistant powered by Groq.
app.post("/api/ai/ask", requireAuth, async (req, res) => {
  const schema = z.object({
    question: z.string().trim().min(3).max(1200),
    history: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().max(2000) })).max(8).optional()
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter a question between 3 and 1,200 characters." });
  if (!process.env.GROQ_API_KEY) return res.status(503).json({ error: "Groq AI is not configured. Add GROQ_API_KEY to backend/.env and restart the backend." });
  try {
    const companyId = await getCompanyForOrganization(pool, req.user.organization_id);
    if (!companyId) return res.status(400).json({ error: "Set up a company before asking accounting questions." });
    const [company, sales, purchases, receivables, payables, topCustomers, topSuppliers, recentJournals, accountBalances] = await Promise.all([
      pool.query("SELECT legal_name, trade_name, state_name, gstin, base_currency FROM companies WHERE id=$1", [companyId]),
      pool.query("SELECT COUNT(*)::int AS count, COALESCE(SUM(total_amount),0)::numeric(18,2) AS total, COALESCE(SUM(amount_received),0)::numeric(18,2) AS received FROM sales_invoices WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query("SELECT COUNT(*)::int AS count, COALESCE(SUM(total_amount),0)::numeric(18,2) AS total, COALESCE(SUM(amount_paid),0)::numeric(18,2) AS paid FROM purchase_bills WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query("SELECT COALESCE(SUM(GREATEST(total_amount-amount_received,0)),0)::numeric(18,2) AS total, COUNT(*) FILTER (WHERE due_date < CURRENT_DATE AND total_amount > amount_received AND status <> 'cancelled')::int AS overdue_count FROM sales_invoices WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query("SELECT COALESCE(SUM(GREATEST(total_amount-amount_paid,0)),0)::numeric(18,2) AS total, COUNT(*) FILTER (WHERE due_date < CURRENT_DATE AND total_amount > amount_paid AND status <> 'cancelled')::int AS overdue_count FROM purchase_bills WHERE company_id=$1 AND status <> 'cancelled'", [companyId]),
      pool.query("SELECT bp.name, COUNT(*)::int AS invoice_count, SUM(GREATEST(si.total_amount-si.amount_received,0))::numeric(18,2) AS outstanding FROM sales_invoices si JOIN business_parties bp ON bp.id=si.customer_id WHERE si.company_id=$1 AND si.status <> 'cancelled' GROUP BY bp.name HAVING SUM(GREATEST(si.total_amount-si.amount_received,0)) > 0 ORDER BY outstanding DESC LIMIT 10", [companyId]),
      pool.query("SELECT bp.name, COUNT(*)::int AS bill_count, SUM(GREATEST(pb.total_amount-pb.amount_paid,0))::numeric(18,2) AS outstanding FROM purchase_bills pb JOIN business_parties bp ON bp.id=pb.supplier_id WHERE pb.company_id=$1 AND pb.status <> 'cancelled' GROUP BY bp.name HAVING SUM(GREATEST(pb.total_amount-pb.amount_paid,0)) > 0 ORDER BY outstanding DESC LIMIT 10", [companyId]),
      pool.query("SELECT entry_number, entry_date, description, total_debit::numeric(18,2) AS debit, total_credit::numeric(18,2) AS credit, status FROM journal_entries WHERE company_id=$1 ORDER BY entry_date DESC, entry_number DESC LIMIT 10", [companyId]),
      pool.query(`SELECT a.code, a.name, a.account_type, COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.debit ELSE 0 END),0)::numeric(18,2) AS debit, COALESCE(SUM(CASE WHEN je.id IS NOT NULL THEN jl.credit ELSE 0 END),0)::numeric(18,2) AS credit FROM accounts a LEFT JOIN journal_lines jl ON jl.account_id=a.id AND jl.company_id=a.company_id LEFT JOIN journal_entries je ON je.id=jl.journal_entry_id AND je.status='posted' WHERE a.company_id=$1 AND a.is_active=TRUE GROUP BY a.code,a.name,a.account_type ORDER BY a.code LIMIT 60`, [companyId])
    ]);
    const context = {
      company: company.rows[0] || {},
      sales: { invoiceCount: sales.rows[0].count, invoicedTotal: Number(sales.rows[0].total), receivedTotal: Number(sales.rows[0].received), outstandingTotal: Number(receivables.rows[0].total), overdueInvoiceCount: receivables.rows[0].overdue_count },
      purchases: { billCount: purchases.rows[0].count, billTotal: Number(purchases.rows[0].total), paidTotal: Number(purchases.rows[0].paid), outstandingTotal: Number(payables.rows[0].total), overdueBillCount: payables.rows[0].overdue_count },
      customersWithHighestOutstanding: topCustomers.rows.map(r=>({ name:r.name, invoiceCount:r.invoice_count, outstanding:Number(r.outstanding) })),
      suppliersWithHighestOutstanding: topSuppliers.rows.map(r=>({ name:r.name, billCount:r.bill_count, outstanding:Number(r.outstanding) })),
      recentJournalEntries: recentJournals.rows,
      accountMovementSummary: accountBalances.rows.map(r=>({code:r.code,name:r.name,type:r.account_type,debit:Number(r.debit),credit:Number(r.credit)}))
    };
    const { default: Groq } = await import("groq-sdk");
    const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
    const model = process.env.GROQ_MODEL || "openai/gpt-oss-120b";
    const history = (parsed.data.history || []).slice(-6).map(m=>({role:m.role,content:m.content.slice(0,1800)}));
    const completion = await groq.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are SoftSpark AutoBooks AI, an accounting information assistant for an Indian business. Answer the user's question using only the supplied company snapshot and conversation. Never invent missing transactions or figures. State when the records do not contain enough information. Clearly distinguish invoiced sales from revenue recognition and never treat sales minus purchases as profit. Do not claim statutory GST/tax compliance. You may explain calculations and suggest checks, but never post, edit, delete, or initiate transactions. Use concise, professional language and INR formatting where relevant. If asked to make a change, explain that this assistant is read-only." },
        { role: "system", content: "Current accounting snapshot (derived from the authenticated user's company records): " + JSON.stringify(context) },
        ...history,
        { role: "user", content: parsed.data.question }
      ],
      temperature: 0.2, max_completion_tokens: 1400, top_p: 1,
      reasoning_effort: process.env.GROQ_REASONING_EFFORT || "medium", stream: false
    });
    const answer = String(completion.choices?.[0]?.message?.content || "").trim();
    if (!answer) throw new Error("Groq returned an empty response");
    res.json({ answer: answer.slice(0, 9000), engine: `Groq ${model}`, generatedAt: new Date().toISOString(), contextSummary: { salesTotal: Number(sales.rows[0].total), purchaseTotal: Number(purchases.rows[0].total), receivables: Number(receivables.rows[0].total), payables: Number(payables.rows[0].total) } });
  } catch (err) {
    console.error("AI assistant error:", err.message);
    res.status(502).json({ error: "The Groq assistant could not answer. Check the API key, model name, internet connection and Groq service status." });
  }
});

app.get("/api/audit-logs", requireAuth, requireRole("owner", "admin", "accountant"), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT al.id, al.action, al.entity_type, al.entity_id, al.details, al.created_at, u.full_name
       FROM audit_logs al LEFT JOIN users u ON u.id=al.user_id
       WHERE al.organization_id=$1 ORDER BY al.created_at DESC LIMIT 200`, [req.user.organization_id]
    );
    res.json({ logs: r.rows });
  } catch (err) {
    console.error("Audit log error:", err.message);
    res.status(500).json({ error: "Could not load audit logs." });
  }
});

app.use((err, _req, res, _next) => {
  console.error("Unhandled API error:", err.message);
  res.status(500).json({ error: "Unexpected server error." });
});

app.listen(port, () => {
  console.log(`SoftSpark AutoBooks API running at http://localhost:${port}`);
  if (jwtSecret.length < 32) console.warn("WARNING: Configure a JWT_SECRET of at least 32 characters in backend/.env.");
});
