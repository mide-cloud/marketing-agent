-- ============================================================================
-- Marketing Agent — Database Schema
-- Run once in your Supabase SQL Editor
-- ============================================================================

CREATE TABLE IF NOT EXISTS lists (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,
  filename        TEXT,
  row_count       INTEGER DEFAULT 0,
  enriched_count  INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'pending',   -- pending | enriching | ready
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS contacts (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  list_id         UUID REFERENCES lists(id) ON DELETE CASCADE,
  company_name    TEXT,
  company_domain  TEXT,
  first_name      TEXT,
  last_name       TEXT,
  email           TEXT,
  title           TEXT,
  linkedin_url    TEXT,
  enriched        BOOLEAN DEFAULT false,
  opted_out       BOOLEAN DEFAULT false,
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS campaigns (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,
  subject         TEXT NOT NULL,
  body_html       TEXT NOT NULL,
  from_name       TEXT,
  status          TEXT DEFAULT 'draft',     -- draft | sending | sent | paused
  sent_count      INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sends (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id      UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  contact_id       UUID REFERENCES contacts(id) ON DELETE CASCADE,
  status           TEXT DEFAULT 'pending',  -- pending | sent | opened | clicked | failed
  sent_at          TIMESTAMPTZ,
  opened_at        TIMESTAMPTZ,
  clicked_at       TIMESTAMPTZ,
  gmail_thread_id  TEXT,
  error_msg        TEXT,
  created_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS settings (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  apollo_key_enc    TEXT,
  gmail_refresh_enc TEXT,
  gmail_email       TEXT,
  gmail_connected   BOOLEAN DEFAULT false,
  from_name         TEXT DEFAULT 'Your Name',
  app_url           TEXT,
  updated_at        TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_contacts_list   ON contacts(list_id);
CREATE INDEX IF NOT EXISTS idx_contacts_email  ON contacts(email);
CREATE INDEX IF NOT EXISTS idx_sends_campaign  ON sends(campaign_id);
CREATE INDEX IF NOT EXISTS idx_sends_contact   ON sends(contact_id);
CREATE INDEX IF NOT EXISTS idx_sends_status    ON sends(status);
