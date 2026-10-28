import { pool } from "./db.js";

const sql = `
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  full_name VARCHAR(160) NOT NULL,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memberships (
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(40) NOT NULL DEFAULT 'owner' CHECK (role IN ('owner','admin','accountant','data_entry','read_only')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS companies (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  legal_name VARCHAR(240) NOT NULL,
  trade_name VARCHAR(240),
  base_currency CHAR(3) NOT NULL DEFAULT 'INR',
  country_code CHAR(2) NOT NULL DEFAULT 'IN',
  state_name VARCHAR(100),
  gstin VARCHAR(15),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS financial_years (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  name VARCHAR(60) NOT NULL,
  start_date DATE NOT NULL,
  end_date DATE NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (end_date >= start_date),
  UNIQUE (company_id, name)
);

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  code VARCHAR(30) NOT NULL,
  name VARCHAR(160) NOT NULL,
  account_type VARCHAR(30) NOT NULL CHECK (account_type IN ('asset','liability','equity','revenue','expense')),
  normal_balance VARCHAR(10) NOT NULL CHECK (normal_balance IN ('debit','credit')),
  parent_id UUID,
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (company_id, code),
  UNIQUE (company_id, id),
  FOREIGN KEY (company_id, parent_id) REFERENCES accounts(company_id, id)
);

CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_companies_org ON companies(organization_id);
CREATE INDEX IF NOT EXISTS idx_financial_years_company ON financial_years(company_id);
CREATE INDEX IF NOT EXISTS idx_accounts_company ON accounts(company_id);

CREATE TABLE IF NOT EXISTS journal_entries (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  financial_year_id UUID NOT NULL REFERENCES financial_years(id) ON DELETE RESTRICT,
  entry_number BIGSERIAL,
  entry_date DATE NOT NULL,
  description VARCHAR(500) NOT NULL,
  reference VARCHAR(120),
  status VARCHAR(20) NOT NULL DEFAULT 'posted' CHECK (status IN ('posted','reversed')),
  total_debit NUMERIC(18,2) NOT NULL CHECK (total_debit > 0),
  total_credit NUMERIC(18,2) NOT NULL CHECK (total_credit > 0),
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (company_id, entry_number),
  CHECK (total_debit = total_credit)
);

CREATE TABLE IF NOT EXISTS journal_lines (
  id UUID PRIMARY KEY,
  journal_entry_id UUID NOT NULL REFERENCES journal_entries(id) ON DELETE RESTRICT,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  account_id UUID NOT NULL,
  line_description VARCHAR(300),
  debit NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (debit >= 0),
  credit NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (credit >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((debit > 0 AND credit = 0) OR (credit > 0 AND debit = 0)),
  FOREIGN KEY (company_id, account_id) REFERENCES accounts(company_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  company_id UUID REFERENCES companies(id) ON DELETE RESTRICT,
  user_id UUID REFERENCES users(id) ON DELETE RESTRICT,
  action VARCHAR(80) NOT NULL,
  entity_type VARCHAR(80) NOT NULL,
  entity_id UUID,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_journal_entries_company_date ON journal_entries(company_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_journal_lines_entry ON journal_lines(journal_entry_id);
CREATE INDEX IF NOT EXISTS idx_journal_lines_account ON journal_lines(company_id, account_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created ON audit_logs(organization_id, created_at DESC);

-- Phase 3: customer/supplier masters, sales invoices and receipts.
CREATE TABLE IF NOT EXISTS business_parties (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  party_type VARCHAR(20) NOT NULL CHECK (party_type IN ('customer','supplier','both')),
  name VARCHAR(200) NOT NULL,
  gstin VARCHAR(15),
  email VARCHAR(254),
  phone VARCHAR(40),
  state_name VARCHAR(100),
  address TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by UUID REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(company_id, id)
);
CREATE INDEX IF NOT EXISTS idx_business_parties_company ON business_parties(company_id, party_type, name);

CREATE TABLE IF NOT EXISTS sales_invoices (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  financial_year_id UUID NOT NULL REFERENCES financial_years(id) ON DELETE RESTRICT,
  customer_id UUID NOT NULL,
  invoice_number VARCHAR(40) NOT NULL,
  invoice_date DATE NOT NULL,
  due_date DATE,
  description VARCHAR(500) NOT NULL,
  taxable_amount NUMERIC(18,2) NOT NULL CHECK (taxable_amount > 0),
  gst_rate NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (gst_rate IN (0,5,12,18,28)),
  cgst_amount NUMERIC(18,2) NOT NULL DEFAULT 0,
  sgst_amount NUMERIC(18,2) NOT NULL DEFAULT 0,
  igst_amount NUMERIC(18,2) NOT NULL DEFAULT 0,
  total_amount NUMERIC(18,2) NOT NULL CHECK (total_amount > 0),
  amount_received NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (amount_received >= 0),
  status VARCHAR(20) NOT NULL DEFAULT 'posted' CHECK (status IN ('posted','partially_paid','paid','cancelled')),
  journal_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(company_id, invoice_number),
  FOREIGN KEY (company_id, customer_id) REFERENCES business_parties(company_id, id) ON DELETE RESTRICT,
  CHECK (total_amount = taxable_amount + cgst_amount + sgst_amount + igst_amount),
  CHECK (amount_received <= total_amount)
);
CREATE INDEX IF NOT EXISTS idx_sales_invoices_company_date ON sales_invoices(company_id, invoice_date DESC);

CREATE TABLE IF NOT EXISTS sales_receipts (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  invoice_id UUID NOT NULL REFERENCES sales_invoices(id) ON DELETE RESTRICT,
  receipt_number VARCHAR(40) NOT NULL,
  receipt_date DATE NOT NULL,
  account_id UUID NOT NULL,
  amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
  reference VARCHAR(120),
  journal_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(company_id, receipt_number),
  FOREIGN KEY (company_id, account_id) REFERENCES accounts(company_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_sales_receipts_invoice ON sales_receipts(invoice_id, receipt_date);

-- Phase 4: supplier purchase bills and supplier payments.
CREATE TABLE IF NOT EXISTS purchase_bills (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  financial_year_id UUID NOT NULL REFERENCES financial_years(id) ON DELETE RESTRICT,
  supplier_id UUID NOT NULL,
  bill_number VARCHAR(60) NOT NULL,
  bill_date DATE NOT NULL,
  due_date DATE,
  description VARCHAR(500) NOT NULL,
  expense_account_id UUID NOT NULL,
  taxable_amount NUMERIC(18,2) NOT NULL CHECK (taxable_amount > 0),
  gst_rate NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (gst_rate IN (0,5,12,18,28)),
  cgst_amount NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (cgst_amount >= 0),
  sgst_amount NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (sgst_amount >= 0),
  igst_amount NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (igst_amount >= 0),
  total_amount NUMERIC(18,2) NOT NULL CHECK (total_amount > 0),
  amount_paid NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (amount_paid >= 0),
  status VARCHAR(20) NOT NULL DEFAULT 'posted' CHECK (status IN ('posted','partially_paid','paid','cancelled')),
  journal_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(company_id, bill_number),
  FOREIGN KEY (company_id, supplier_id) REFERENCES business_parties(company_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (company_id, expense_account_id) REFERENCES accounts(company_id, id) ON DELETE RESTRICT,
  CHECK (total_amount = taxable_amount + cgst_amount + sgst_amount + igst_amount),
  CHECK (amount_paid <= total_amount)
);
CREATE INDEX IF NOT EXISTS idx_purchase_bills_company_date ON purchase_bills(company_id, bill_date DESC);

CREATE TABLE IF NOT EXISTS supplier_payments (
  id UUID PRIMARY KEY,
  company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  bill_id UUID NOT NULL REFERENCES purchase_bills(id) ON DELETE RESTRICT,
  payment_number VARCHAR(50) NOT NULL,
  payment_date DATE NOT NULL,
  account_id UUID NOT NULL,
  amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
  reference VARCHAR(120),
  journal_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(company_id, payment_number),
  FOREIGN KEY (company_id, account_id) REFERENCES accounts(company_id, id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_supplier_payments_bill ON supplier_payments(bill_id, payment_date);
-- Release 2: additive business operations. Safe to run against an existing Release 1 database.
CREATE TABLE IF NOT EXISTS inventory_items (
 id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
 sku VARCHAR(80) NOT NULL, name VARCHAR(200) NOT NULL, description TEXT,
 unit VARCHAR(30) NOT NULL DEFAULT 'unit', opening_quantity NUMERIC(18,3) NOT NULL DEFAULT 0 CHECK(opening_quantity >= 0),
 reorder_level NUMERIC(18,3) NOT NULL DEFAULT 0 CHECK(reorder_level >= 0), unit_cost NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK(unit_cost >= 0),
 is_active BOOLEAN NOT NULL DEFAULT TRUE, created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(company_id, sku), UNIQUE(company_id,id)
);
CREATE TABLE IF NOT EXISTS inventory_movements (
 id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
 item_id UUID NOT NULL,
 movement_date DATE NOT NULL, movement_type VARCHAR(20) NOT NULL CHECK(movement_type IN ('opening','receipt','issue','adjustment_in','adjustment_out')),
 quantity NUMERIC(18,3) NOT NULL CHECK(quantity > 0), unit_cost NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK(unit_cost >= 0),
 reference VARCHAR(120), notes TEXT, created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(company_id,item_id) REFERENCES inventory_items(company_id,id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_inventory_movements_company_date ON inventory_movements(company_id,movement_date DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_journal_lines_company_id_unique ON journal_lines(company_id,id);
CREATE TABLE IF NOT EXISTS bank_statement_lines (
 id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
 account_id UUID NOT NULL, statement_date DATE NOT NULL, description VARCHAR(500) NOT NULL,
 reference VARCHAR(120), amount NUMERIC(18,2) NOT NULL CHECK(amount <> 0),
 matched_journal_line_id UUID, matched_at TIMESTAMPTZ, matched_by UUID REFERENCES users(id),
 import_batch UUID NOT NULL, created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(company_id,account_id) REFERENCES accounts(company_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(company_id,matched_journal_line_id) REFERENCES journal_lines(company_id,id) ON DELETE RESTRICT,
 UNIQUE(company_id,account_id,matched_journal_line_id)
);
CREATE INDEX IF NOT EXISTS idx_bank_statement_company_account ON bank_statement_lines(company_id,account_id,statement_date DESC);
CREATE TABLE IF NOT EXISTS approval_requests (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
 request_type VARCHAR(40) NOT NULL CHECK(request_type IN ('journal')),
 title VARCHAR(240) NOT NULL, payload JSONB NOT NULL,
 status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 requested_by UUID NOT NULL REFERENCES users(id), reviewed_by UUID REFERENCES users(id),
 reviewer_note TEXT, journal_entry_id UUID REFERENCES journal_entries(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_org_status ON approval_requests(organization_id,status,created_at DESC);


-- Release 3: Enterprise master data and consolidation workpapers. Additive only.
CREATE TABLE IF NOT EXISTS enterprise_entities (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 legal_name VARCHAR(240) NOT NULL, entity_code VARCHAR(40) NOT NULL, currency CHAR(3) NOT NULL DEFAULT 'INR',
 country_code CHAR(2) NOT NULL DEFAULT 'IN', tax_identifier VARCHAR(40), status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')),
 created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(organization_id,entity_code)
);
CREATE TABLE IF NOT EXISTS enterprise_branches (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 entity_id UUID NOT NULL REFERENCES enterprise_entities(id) ON DELETE RESTRICT, branch_code VARCHAR(40) NOT NULL,
 name VARCHAR(200) NOT NULL, address TEXT, manager_name VARCHAR(160), status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')),
 created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(entity_id,branch_code)
);
CREATE TABLE IF NOT EXISTS cost_centres (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 centre_code VARCHAR(40) NOT NULL, name VARCHAR(200) NOT NULL, department VARCHAR(160), owner_name VARCHAR(160), status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')),
 created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(organization_id,centre_code)
);
CREATE TABLE IF NOT EXISTS enterprise_budgets (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 budget_name VARCHAR(200) NOT NULL, period_start DATE NOT NULL, period_end DATE NOT NULL,
 status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','closed')),
 created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK(period_end>=period_start)
);
CREATE TABLE IF NOT EXISTS enterprise_budget_lines (
 id UUID PRIMARY KEY, budget_id UUID NOT NULL REFERENCES enterprise_budgets(id) ON DELETE CASCADE,
 account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT, cost_centre_id UUID REFERENCES cost_centres(id) ON DELETE RESTRICT,
 planned_amount NUMERIC(18,2) NOT NULL CHECK(planned_amount>=0), notes VARCHAR(500), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(budget_id,account_id,cost_centre_id)
);
CREATE TABLE IF NOT EXISTS intercompany_transactions (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 source_entity_id UUID NOT NULL REFERENCES enterprise_entities(id) ON DELETE RESTRICT,
 target_entity_id UUID NOT NULL REFERENCES enterprise_entities(id) ON DELETE RESTRICT,
 transaction_date DATE NOT NULL, reference VARCHAR(120), description VARCHAR(500) NOT NULL,
 amount NUMERIC(18,2) NOT NULL CHECK(amount>0), currency CHAR(3) NOT NULL DEFAULT 'INR',
 status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','reviewed','eliminated')),
 created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK(source_entity_id<>target_entity_id)
);
CREATE TABLE IF NOT EXISTS consolidation_eliminations (
 id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 transaction_id UUID REFERENCES intercompany_transactions(id) ON DELETE RESTRICT,
 elimination_date DATE NOT NULL, description VARCHAR(500) NOT NULL, amount NUMERIC(18,2) NOT NULL CHECK(amount>0),
 status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved')),
 created_by UUID REFERENCES users(id), approved_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_enterprise_entities_org ON enterprise_entities(organization_id,status);
CREATE INDEX IF NOT EXISTS idx_enterprise_branches_entity ON enterprise_branches(entity_id,status);
CREATE INDEX IF NOT EXISTS idx_cost_centres_org ON cost_centres(organization_id,status);
CREATE INDEX IF NOT EXISTS idx_enterprise_budgets_org ON enterprise_budgets(organization_id,period_start);
CREATE INDEX IF NOT EXISTS idx_intercompany_org_date ON intercompany_transactions(organization_id,transaction_date DESC);
CREATE INDEX IF NOT EXISTS idx_eliminations_org_date ON consolidation_eliminations(organization_id,elimination_date DESC);

`;

try {
  await pool.query(sql);
  console.log("Database schema initialized successfully.");
} catch (err) {
  console.error("Database initialization failed:", err.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
