# VaultLink Database Architecture & Security Model

This document describes the Supabase PostgreSQL database architecture, schema design, zero-knowledge security principles, audit model, and execution instructions for **VaultLink Secure Handover Room**.

---

## 1. The `secrets` Table

The `secrets` table is the primary persistence layer for confidential handovers. It tracks secret metadata, security constraints, cryptographic envelopes, view quotas, and lifecycle states.

### Column Specifications:
- `id` (`TEXT PRIMARY KEY`): Unique nanoid or cryptographically secure random token identifying the handover link.
- `ciphertext` (`TEXT`): AES-GCM encrypted payload (zero-knowledge encrypted string).
- `iv` (`TEXT`): Initialization Vector (nonce) used for the AES-GCM encryption cipher.
- `auth_tag` (`TEXT`): Cryptographic authentication tag verifying payload integrity and authenticity.
- `passphrase_hash` (`TEXT`): Secure salted hash (e.g. Argon2id or SHA-256) of the recipient passphrase (optional).
- `access_code_hash` (`TEXT`): Secure salted hash of the secondary one-time verification code (optional).
- `management_token_hash` (`TEXT NOT NULL`): Secure hash of the sender's management/burn token.
- `expires_at` (`TIMESTAMPTZ NOT NULL`): Absolute deadline timestamp after which the secret is destroyed.
- `available_at` (`TIMESTAMPTZ NOT NULL`): Timestamp indicating when the secret becomes unlockable (for scheduled releases).
- `max_views` (`INTEGER NOT NULL DEFAULT 1`): Maximum allowable reveal operations (restricted between 1 and 5).
- `views_remaining` (`INTEGER NOT NULL DEFAULT 1`): Counter tracking remaining reveals allowed before burn.
- `status` (`TEXT NOT NULL DEFAULT 'active'`): Lifecycle state (`scheduled`, `active`, `revealed`, `acknowledged`, `expired`, `revoked`, `burned`).
- `created_at` (`TIMESTAMPTZ NOT NULL DEFAULT NOW()`): Creation timestamp.
- `revealed_at` (`TIMESTAMPTZ`): Timestamp of the initial successful decryption/reveal.
- `acknowledged_at` (`TIMESTAMPTZ`): Timestamp when recipient acknowledges receipt.
- `revoked_at` (`TIMESTAMPTZ`): Timestamp if manually burned or revoked by sender.

---

## 2. Zero-Knowledge Cryptography: Why Only Encrypted Values Are Saved

VaultLink is built around an **End-to-End Zero-Knowledge Trust Model**:
- **Zero Plaintext Storage**: Plaintext secrets, passwords, or credentials are never stored in the database.
- **Envelope Encryption**: The payload is stored strictly as `ciphertext`, `iv`, and `auth_tag`. Without the master key / decryption secret, the database records are indistinguishable from random noise.
- **Cryptographic Shredding**: When a secret is burned, expired, or revoked, the `ciphertext`, `iv`, `auth_tag`, and credential hashes are permanently nullified (cryptographically shredded), leaving no trace of the encrypted material in the database.

---

## 3. Why Hashes Are Used for Passphrases, Access Codes, and Management Tokens

1. **Passphrase Hash (`passphrase_hash`)**: Ensures that even if an attacker gains read access to the database, they cannot derive the required passphrase or use it to assist brute-force attacks against the encrypted payload.
2. **Access Code Hash (`access_code_hash`)**: Protects secondary out-of-band verification codes against observation.
3. **Management Token Hash (`management_token_hash`)**: Protects the sender's revocation/burn capabilities. Only possessing the plaintext management token allows issuing manual burn or status inspection requests; the database only knows its one-way hash.

---

## 4. The `secret_events` Table (Safe Audit Trail)

The `secret_events` table maintains an immutable audit trail of secret lifecycle events.

### Security Guarantees:
- **Zero Sensitive Data**: It **NEVER** stores plaintext secrets, access codes, passphrases, master keys, ciphertext, IVs, or auth tags.
- **Permitted Event Types**:
  - `created`: Handover room created.
  - `scheduled`: Handover scheduled for future release.
  - `activated`: Scheduled secret reached availability window.
  - `verification_failed`: Failed passphrase/code attempt.
  - `verification_passed`: Recipient verified successfully.
  - `revealed`: Secret decrypted and shown to recipient.
  - `acknowledged`: Recipient confirmed receipt.
  - `panic_burned`: Sender or recipient triggered emergency destruction.
  - `expired`: Time-to-live elapsed.
  - `bot_blocked`: Automated scraping attempt detected and halted.

---

## 5. Row Level Security (RLS) & Defense-in-Depth

- Direct browser-to-database connections (anonymous `anon` role or standard `authenticated` role) are **completely denied**.
- All SQL operations are mediated through the Node.js Express backend using the secure server-only `SUPABASE_SECRET_KEY` (`service_role`).
- This design prevents API scraping, unauthorized table enumerations, or client-side tampering with verification counters or status columns.

---

## 6. How to Run the SQL in Supabase SQL Editor

1. Open your browser and navigate to your [Supabase Project Dashboard](https://supabase.com/dashboard).
2. In the left navigation menu, click the **SQL Editor** icon (`>_`).
3. Click **New query** (or **+** tab).
4. Copy the entire contents of [`supabase-schema.sql`](../supabase-schema.sql).
5. Paste the SQL into the editor window.
6. Click the green **Run** button (or press `Ctrl` + `Enter` / `Cmd` + `Enter`).
7. Inspect the output log to ensure:
   - `CREATE TABLE secrets` succeeded.
   - `CREATE TABLE secret_events` succeeded.
   - Indexes and constraints were applied without errors.
   - Supabase Table Editor confirms Row Level Security (RLS) is enabled for both tables.
