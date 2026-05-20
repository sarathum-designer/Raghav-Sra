-- ================================================================
--  RAGHAV REALTY -- SUPABASE SETUP
--  Run in: Supabase Dashboard > SQL Editor > New Query > Run All
-- ================================================================


-- ---------------------------------------------------------------
-- 1. CORE TABLES
-- ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS owners (
  id              UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  house_id        TEXT        UNIQUE NOT NULL,
  name            TEXT        NOT NULL,
  email           TEXT,
  phone           TEXT,
  password_hash   TEXT        NOT NULL,
  verified        BOOLEAN     DEFAULT NULL,
  verified_at     TIMESTAMPTZ,
  rejection_notes TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS documents (
  id           UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  owner_id     UUID        NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
  doc_type     TEXT        NOT NULL
                           CHECK (doc_type IN ('govt_id','ownership_doc','tax_bill','utility_bill')),
  file_name    TEXT        NOT NULL,
  file_path    TEXT        NOT NULL,
  file_url     TEXT,
  status       TEXT        DEFAULT 'pending'
                           CHECK (status IN ('pending','approved','rejected')),
  review_notes TEXT,
  uploaded_at  TIMESTAMPTZ DEFAULT NOW(),
  reviewed_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS admins (
  id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  display_name  TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);


-- ---------------------------------------------------------------
-- 2. SECURITY TABLES
-- ---------------------------------------------------------------

-- Tracks failed logins for brute-force rate limiting
CREATE TABLE IF NOT EXISTS login_attempts (
  id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  identifier TEXT        NOT NULL,
  ip_address TEXT,
  success    BOOLEAN     DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Immutable audit trail
CREATE TABLE IF NOT EXISTS audit_log (
  id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  event      TEXT        NOT NULL,
  actor_id   UUID,
  actor_type TEXT,
  target_id  UUID,
  details    JSONB,
  ip_address TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);


-- ---------------------------------------------------------------
-- 3. INDEXES
-- ---------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_owners_house_id
  ON owners(house_id);

CREATE INDEX IF NOT EXISTS idx_docs_owner_id
  ON documents(owner_id);

CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup
  ON login_attempts(identifier, success, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_actor
  ON audit_log(actor_id, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_event
  ON audit_log(event, created_at);


-- ---------------------------------------------------------------
-- 4. ROW LEVEL SECURITY
-- The API uses the service_role key which bypasses RLS.
-- These policies block direct access via the public/anon key.
-- ---------------------------------------------------------------

ALTER TABLE owners         ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents      ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins         ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log      ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "block_direct_owners"         ON owners;
DROP POLICY IF EXISTS "block_direct_documents"      ON documents;
DROP POLICY IF EXISTS "block_direct_admins"         ON admins;
DROP POLICY IF EXISTS "block_direct_login_attempts" ON login_attempts;
DROP POLICY IF EXISTS "block_direct_audit_log"      ON audit_log;

CREATE POLICY "block_direct_owners"
  ON owners FOR ALL USING (false);

CREATE POLICY "block_direct_documents"
  ON documents FOR ALL USING (false);

CREATE POLICY "block_direct_admins"
  ON admins FOR ALL USING (false);

CREATE POLICY "block_direct_login_attempts"
  ON login_attempts FOR ALL USING (false);

CREATE POLICY "block_direct_audit_log"
  ON audit_log FOR ALL USING (false);


-- ---------------------------------------------------------------
-- 5. STORAGE BUCKET (private, 8 MB limit)
-- type = 'STANDARD' is required -- omitting it caused the error
-- ---------------------------------------------------------------

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types, type)
VALUES (
  'documents',
  'documents',
  false,
  8388608,
  ARRAY['image/jpeg', 'image/png', 'application/pdf']::text[],
  'STANDARD'
)
ON CONFLICT (id) DO NOTHING;


-- ---------------------------------------------------------------
-- 6. ADMIN ACCOUNT  (login: Viralimam / Shhhhhhh)
-- bcrypt hash of "Shhhhhhh" with saltRounds=10
-- ---------------------------------------------------------------

INSERT INTO admins (username, display_name, password_hash)
VALUES (
  'viralimam',
  'Viralimam',
  '$2a$10$9Olo1YcaBEyOI0NSPEY1ueGcX802WSvEkkCvqf4Zma0.j.HbfC7Y2'
)
ON CONFLICT (username) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  display_name  = EXCLUDED.display_name;


-- ---------------------------------------------------------------
-- 7. DUMMY LAND OWNERS -- Nalanda
-- Default login password for all: Password@123
-- bcrypt hash of "Password@123" with saltRounds=10
-- ---------------------------------------------------------------

INSERT INTO owners (house_id, name, phone, password_hash) VALUES
  ('NAL-001', 'Rajesh Kumar',  '9876543210', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-002', 'Priya Sharma',  '9876543211', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-003', 'Amit Patel',    '9876543212', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-004', 'Sunita Devi',   '9876543213', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-005', 'Ramesh Singh',  '9876543214', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-006', 'Kavita Mishra', '9876543215', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-007', 'Suresh Yadav',  '9876543216', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-008', 'Meena Gupta',   '9876543217', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-009', 'Dinesh Tiwari', '9876543218', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6'),
  ('NAL-010', 'Anita Verma',   '9876543219', '$2a$10$GHXnmOnL3Qy2nCVOhfJZHuU7WkiQGeR0sqrMPTwinXrhgyDQP4VH6')
ON CONFLICT (house_id) DO NOTHING;
