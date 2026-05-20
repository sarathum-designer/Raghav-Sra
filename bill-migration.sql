-- ─────────────────────────────────────────────────────────────────
-- Raghav Realty — Bill Claims migration
-- Run this once in Supabase Dashboard → SQL Editor
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS bill_claims (
  id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id      uuid         NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
  bill_type     text         NOT NULL CHECK (bill_type IN ('electricity', 'gas', 'water', 'other')),
  bill_month    text         NOT NULL,
  claim_amount  numeric(10,2),
  file_name     text         NOT NULL,
  file_path     text         NOT NULL,
  file_url      text,
  status        text         NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'approved', 'rejected')),
  notes         text,
  created_at    timestamptz  NOT NULL DEFAULT now(),
  approved_at   timestamptz
);

-- Block all direct access via the anon/public key
ALTER TABLE bill_claims ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_all_bill_claims" ON bill_claims FOR ALL TO anon USING (false);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_bill_claims_owner  ON bill_claims(owner_id);
CREATE INDEX IF NOT EXISTS idx_bill_claims_status ON bill_claims(status);
