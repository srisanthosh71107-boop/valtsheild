-- ============================================================================
-- VaultLink Secure Handover Room - Database Schema
-- Production-Ready SQL Schema for Supabase Postgres
-- ============================================================================

-- Enable pgcrypto extension for secure cryptographic operations if required
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. SECRETS TABLE
-- Stores zero-knowledge encrypted payloads, authorization hashes, lifecycle
-- state, expiration schedules, and view limits.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    ciphertext TEXT,
    iv TEXT,
    auth_tag TEXT,
    passphrase_hash TEXT,
    access_code_hash TEXT,
    management_token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    max_views INTEGER NOT NULL DEFAULT 1,
    views_remaining INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revealed_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    -- Valid status values constraint
    CONSTRAINT secrets_status_check CHECK (
        status IN ('scheduled', 'active', 'revealed', 'acknowledged', 'expired', 'revoked', 'burned')
    ),

    -- Max views must be between 1 and 5
    CONSTRAINT secrets_max_views_check CHECK (
        max_views BETWEEN 1 AND 5
    ),

    -- Views remaining must be between 0 and max_views
    CONSTRAINT secrets_views_remaining_check CHECK (
        views_remaining >= 0 AND views_remaining <= max_views
    ),

    -- Expiration must be strictly later than availability timestamp
    CONSTRAINT secrets_timeline_check CHECK (
        expires_at > available_at
    ),

    -- Cryptographic payload integrity constraint:
    -- ciphertext, iv, auth_tag, passphrase_hash, and access_code_hash
    -- may become NULL only after a secret is burned, expired, or revoked
    CONSTRAINT secrets_payload_integrity_check CHECK (
        (status IN ('burned', 'expired', 'revoked')) OR 
        (ciphertext IS NOT NULL AND iv IS NOT NULL AND auth_tag IS NOT NULL)
    )
);

-- Indexes for performance and query optimization
CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets(expires_at);
CREATE INDEX IF NOT EXISTS secrets_available_at_idx ON secrets(available_at);
CREATE INDEX IF NOT EXISTS secrets_status_idx ON secrets(status);

-- Enable Row Level Security (RLS)
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 2. SECRET_EVENTS TABLE
-- Audit log recording lifecycle actions (creation, verification, access, burn).
-- Never stores plaintext secrets, encryption keys, or cryptographic payloads.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS secret_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    secret_id TEXT REFERENCES secrets(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb,

    -- Allowed event types constraint
    CONSTRAINT secret_events_type_check CHECK (
        event_type IN (
            'created',
            'scheduled',
            'activated',
            'verification_failed',
            'verification_passed',
            'revealed',
            'acknowledged',
            'panic_burned',
            'expired',
            'bot_blocked'
        )
    )
);

-- Index for querying audit events in reverse chronological order
CREATE INDEX IF NOT EXISTS secret_events_secret_id_created_at_idx ON secret_events(secret_id, created_at DESC);

-- Enable Row Level Security (RLS)
ALTER TABLE secret_events ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 3. VERIFICATION_TOKENS TABLE
-- Server-only store for temporary SHA-256 hashed verification tokens.
-- Allows single-use, 2-minute time-window access for secret revelation in Step 8.
-- Never stores raw tokens.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verification_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for token lookup and expiration sweeping
CREATE INDEX IF NOT EXISTS verification_tokens_secret_id_idx ON verification_tokens(secret_id);
CREATE INDEX IF NOT EXISTS verification_tokens_expires_at_idx ON verification_tokens(expires_at);

-- Enable Row Level Security (RLS)
ALTER TABLE verification_tokens ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 4. ROW LEVEL SECURITY (RLS) ACCESS POLICIES
-- Strict Zero-Trust access control: Deny all direct public/anonymous and
-- authenticated browser access to all tables.
-- The Express backend server communicates exclusively via the SUPABASE_SECRET_KEY
-- (service_role), which securely bypasses RLS on the server side.
-- ----------------------------------------------------------------------------
REVOKE ALL ON secrets FROM anon, authenticated;
REVOKE ALL ON secret_events FROM anon, authenticated;
REVOKE ALL ON verification_tokens FROM anon, authenticated;

-- ----------------------------------------------------------------------------
-- 5. ATOMIC SECRET REVEAL & SHREDDING RPC FUNCTION
-- Executes all verification token validation, secret state inspection,
-- quota decrement, cryptographic shredding, and event logging within a single
-- atomic transaction with row-level locks (FOR UPDATE).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION reveal_secret_atomically(
    p_secret_id TEXT,
    p_token_hash TEXT,
    p_now TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE (
    ciphertext TEXT,
    iv TEXT,
    auth_tag TEXT,
    views_remaining INTEGER,
    burned BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_token RECORD;
    v_secret RECORD;
    v_new_views INTEGER;
    v_ciphertext TEXT;
    v_iv TEXT;
    v_auth_tag TEXT;
    v_burned BOOLEAN;
BEGIN
    -- 1. Lock and validate matching verification token row
    SELECT * INTO v_token
    FROM verification_tokens
    WHERE token_hash = p_token_hash
      AND secret_id = p_secret_id
    FOR UPDATE;

    -- 2-5. Verify token existence, matching secret_id, unused state, and unexpired validity
    IF NOT FOUND OR v_token IS NULL THEN
        RETURN;
    END IF;

    IF v_token.used_at IS NOT NULL THEN
        RETURN;
    END IF;

    IF v_token.expires_at <= p_now THEN
        RETURN;
    END IF;

    -- 6. Lock matching secret row
    SELECT * INTO v_secret
    FROM secrets
    WHERE id = p_secret_id
    FOR UPDATE;

    -- 7-10. Verify secret existence, active status, availability schedule, expiration, and remaining views
    IF NOT FOUND OR v_secret IS NULL THEN
        RETURN;
    END IF;

    IF v_secret.status <> 'active' THEN
        RETURN;
    END IF;

    IF p_now < v_secret.available_at THEN
        RETURN;
    END IF;

    IF p_now >= v_secret.expires_at THEN
        RETURN;
    END IF;

    IF v_secret.views_remaining <= 0 THEN
        RETURN;
    END IF;

    -- 11. Mark verification token as used
    UPDATE verification_tokens
    SET used_at = p_now
    WHERE id = v_token.id;

    -- Extract encrypted materials to return to server
    v_ciphertext := v_secret.ciphertext;
    v_iv := v_secret.iv;
    v_auth_tag := v_secret.auth_tag;
    v_new_views := v_secret.views_remaining - 1;

    -- 12-15. Mutate secret state and quota
    IF v_new_views <= 0 THEN
        -- Cryptographically shred all secret material and mark burned
        UPDATE secrets
        SET ciphertext = NULL,
            iv = NULL,
            auth_tag = NULL,
            passphrase_hash = NULL,
            access_code_hash = NULL,
            views_remaining = 0,
            status = 'burned',
            revealed_at = p_now
        WHERE id = p_secret_id;
        v_burned := TRUE;
    ELSE
        -- Decrement views remaining, keep status active
        UPDATE secrets
        SET views_remaining = v_new_views,
            revealed_at = COALESCE(revealed_at, p_now)
        WHERE id = p_secret_id;
        v_burned := FALSE;
    END IF;

    -- 13. Return encrypted fields only to Express backend
    RETURN QUERY SELECT v_ciphertext, v_iv, v_auth_tag, v_new_views, v_burned;
END;
$$;

-- Revoke execute from public/anon/authenticated roles, grant exclusively to service_role
REVOKE EXECUTE ON FUNCTION reveal_secret_atomically(TEXT, TEXT, TIMESTAMPTZ) FROM anon, authenticated, public;
GRANT EXECUTE ON FUNCTION reveal_secret_atomically(TEXT, TEXT, TIMESTAMPTZ) TO service_role;

-- ----------------------------------------------------------------------------
-- 6. AUTOMATIC LIFECYCLE MAINTENANCE RPC FUNCTION
-- Activates scheduled secrets reaching available_at and expires old secrets
-- reaching expires_at while atomically removing all cryptographic material.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION maintain_secret_lifecycle(
    p_now TIMESTAMPTZ DEFAULT NOW()
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_activated_ids TEXT[] := ARRAY[]::TEXT[];
    v_expired_ids TEXT[] := ARRAY[]::TEXT[];
BEGIN
    -- 1. Activate scheduled secrets that reached availability and are not yet expired
    WITH to_activate AS (
        SELECT id
        FROM secrets
        WHERE status = 'scheduled'
          AND available_at <= p_now
          AND expires_at > p_now
        FOR UPDATE SKIP LOCKED
    ),
    updated_activate AS (
        UPDATE secrets
        SET status = 'active'
        WHERE id IN (SELECT id FROM to_activate)
          AND status = 'scheduled'
        RETURNING id
    )
    SELECT COALESCE(array_agg(id), ARRAY[]::TEXT[]) INTO v_activated_ids FROM updated_activate;

    -- 2. Expire old secrets (scheduled or active) whose expiration timestamp has arrived
    WITH to_expire AS (
        SELECT id
        FROM secrets
        WHERE status IN ('scheduled', 'active')
          AND expires_at <= p_now
        FOR UPDATE SKIP LOCKED
    ),
    updated_expire AS (
        UPDATE secrets
        SET ciphertext = NULL,
            iv = NULL,
            auth_tag = NULL,
            passphrase_hash = NULL,
            access_code_hash = NULL,
            status = 'expired'
        WHERE id IN (SELECT id FROM to_expire)
          AND status IN ('scheduled', 'active')
        RETURNING id
    )
    SELECT COALESCE(array_agg(id), ARRAY[]::TEXT[]) INTO v_expired_ids FROM updated_expire;

    RETURN jsonb_build_object(
        'activated_ids', to_jsonb(v_activated_ids),
        'expired_ids', to_jsonb(v_expired_ids)
    );
END;
$$;

-- Revoke execute from public/anon/authenticated roles, grant exclusively to service_role
REVOKE EXECUTE ON FUNCTION maintain_secret_lifecycle(TIMESTAMPTZ) FROM anon, authenticated, public;
GRANT EXECUTE ON FUNCTION maintain_secret_lifecycle(TIMESTAMPTZ) TO service_role;

-- ----------------------------------------------------------------------------
-- 7. ATOMIC PANIC BURN RPC FUNCTION
-- Atomically revokes and cryptographically shreds a secret in scheduled or
-- active status, transitioning status to 'revoked' and recording revoked_at.
-- Returns the revoked secret row if successful, or nothing if invalid/already-ended.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION panic_burn_secret_atomically(
    p_secret_id TEXT,
    p_now TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE (
    id TEXT,
    status TEXT,
    revoked_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_secret RECORD;
BEGIN
    -- 1. Lock matching secret row
    SELECT * INTO v_secret
    FROM secrets
    WHERE secrets.id = p_secret_id
    FOR UPDATE;

    -- 2. Verify existence and allowed status (only scheduled or active)
    IF NOT FOUND OR v_secret IS NULL THEN
        RETURN;
    END IF;

    IF v_secret.status NOT IN ('scheduled', 'active') THEN
        RETURN;
    END IF;

    -- 3. Cryptographically shred all secret material and mark revoked
    UPDATE secrets
    SET ciphertext = NULL,
        iv = NULL,
        auth_tag = NULL,
        passphrase_hash = NULL,
        access_code_hash = NULL,
        status = 'revoked',
        revoked_at = p_now
    WHERE secrets.id = p_secret_id;

    RETURN QUERY
    SELECT p_secret_id, 'revoked'::TEXT, p_now;
END;
$$;

-- Revoke execute from public/anon/authenticated roles, grant exclusively to service_role
REVOKE EXECUTE ON FUNCTION panic_burn_secret_atomically(TEXT, TIMESTAMPTZ) FROM anon, authenticated, public;
GRANT EXECUTE ON FUNCTION panic_burn_secret_atomically(TEXT, TIMESTAMPTZ) TO service_role;

-- ----------------------------------------------------------------------------
-- 8. ACKNOWLEDGEMENT TOKENS TABLE (Server-Only)
-- Ephemeral single-use SHA-256 tokens generated after a successful reveal,
-- allowing the recipient to acknowledge receipt within 15 minutes.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acknowledgement_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS acknowledgement_tokens_secret_id_idx
ON acknowledgement_tokens(secret_id);

CREATE INDEX IF NOT EXISTS acknowledgement_tokens_expires_at_idx
ON acknowledgement_tokens(expires_at);

-- Enable Row Level Security (RLS)
ALTER TABLE acknowledgement_tokens ENABLE ROW LEVEL SECURITY;

-- Revoke all permissions from anon, authenticated, and public
REVOKE ALL ON acknowledgement_tokens FROM anon, authenticated, public;
GRANT ALL ON acknowledgement_tokens TO service_role;

-- ----------------------------------------------------------------------------
-- 9. ATOMIC ACKNOWLEDGE RPC FUNCTION
-- Atomically validates a single-use acknowledgement token, marks it used,
-- updates secrets.acknowledged_at (if currently null), and returns the timestamp.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION acknowledge_secret_atomically(
    p_secret_id TEXT,
    p_token_hash TEXT,
    p_now TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE (
    secret_id TEXT,
    acknowledged_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_token RECORD;
    v_secret RECORD;
    v_ack_time TIMESTAMPTZ;
BEGIN
    -- 1. Lock matching acknowledgement token row using FOR UPDATE
    SELECT * INTO v_token
    FROM acknowledgement_tokens
    WHERE acknowledgement_tokens.token_hash = p_token_hash
      AND acknowledgement_tokens.secret_id = p_secret_id
    FOR UPDATE;

    -- 2. Validate token existence, expiration, and unused status
    IF NOT FOUND OR v_token IS NULL THEN
        RETURN;
    END IF;

    IF v_token.expires_at <= p_now OR v_token.used_at IS NOT NULL THEN
        RETURN;
    END IF;

    -- 3. Lock matching secret row using FOR UPDATE
    SELECT * INTO v_secret
    FROM secrets
    WHERE secrets.id = p_secret_id
    FOR UPDATE;

    -- 4. Check secret existence and valid status
    IF NOT FOUND OR v_secret IS NULL THEN
        RETURN;
    END IF;

    -- Do not change or acknowledge expired or revoked secrets
    IF v_secret.status IN ('revoked', 'expired') THEN
        RETURN;
    END IF;

    -- 5. Mark acknowledgement token used_at
    UPDATE acknowledgement_tokens
    SET used_at = p_now
    WHERE id = v_token.id;

    -- 6. Update secrets.acknowledged_at only when it is currently NULL
    -- Preserve current secret status:
    -- Burned remains burned. Active remains active for multi-view secret.
    IF v_secret.acknowledged_at IS NULL THEN
        UPDATE secrets
        SET acknowledged_at = p_now
        WHERE id = p_secret_id;
        v_ack_time := p_now;
    ELSE
        v_ack_time := v_secret.acknowledged_at;
    END IF;

    -- 7. Return acknowledgement timestamp on success
    RETURN QUERY
    SELECT p_secret_id, v_ack_time;
END;
$$;

-- Revoke execute from anon and authenticated roles, grant only to service_role
REVOKE EXECUTE ON FUNCTION acknowledge_secret_atomically(TEXT, TEXT, TIMESTAMPTZ) FROM anon, authenticated, public;
GRANT EXECUTE ON FUNCTION acknowledge_secret_atomically(TEXT, TEXT, TIMESTAMPTZ) TO service_role;




