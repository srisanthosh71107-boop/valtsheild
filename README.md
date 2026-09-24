# VaultLink - Secure Handover Room

VaultLink is a secure one-time secret-sharing platform. It allows a sender to encrypt a password, API key, or credential, send it through a self-destructing link, and allow recipient access only after verification.

---

## 🛠 Required Software

- **Node.js**: Version 20 or higher
- **Supabase Account**: A cloud Postgres database instance from [Supabase](https://supabase.com)

---

## 🚀 Steps to Create a Supabase Project

1. Sign in or register at [Supabase](https://supabase.com/).
2. Click **New Project** in the Supabase dashboard.
3. Select your organization, specify a **Project Name** (e.g., `vaultlink`), create a strong database password, and choose your preferred deployment region.
4. Once the project finishes provisioning, navigate to **Project Settings** (gear icon in sidebar) > **API**.
5. Copy the **Project URL** and paste it into your `.env` file as `SUPABASE_URL`.
6. Under **Project API keys**, copy the server-only **Secret Key** (`service_role` secret key) and paste it into your `.env` file as `SUPABASE_SECRET_KEY`.
   > ⚠️ **SECURITY WARNING:** Never expose `SUPABASE_SECRET_KEY` in frontend code, client-side bundles, API responses, logs, or public repositories.

---

## 🗄️ Database Setup

Follow these steps to deploy the database schema to your Supabase Postgres database:

1. Open your **Supabase Dashboard** and select your project.
2. In the left navigation sidebar, select **SQL Editor** (`>_`).
3. Click **New query** (or the **+** tab).
4. Copy all contents from [`supabase-schema.sql`](supabase-schema.sql).
5. Paste the SQL query into the SQL Editor.
6. Click **Run** (or press `Ctrl` + `Enter` / `Cmd` + `Enter`).
7. Confirm in the **Table Editor** that the `secrets` and `secret_events` tables appear.
8. Confirm that **Row Level Security (RLS)** is enabled for both tables.

For detailed documentation on table design and zero-knowledge security rationale, refer to [`database/README.md`](database/README.md).

---

## 📦 Installation and Run Commands

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```
   Open `.env` and set your credentials:
   ```env
   PORT=3000
   APP_BASE_URL=http://localhost:3000
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_SECRET_KEY=your-supabase-secret-service-key
   VAULT_MASTER_KEY=your-base64-32-byte-master-key
   BCRYPT_SALT_ROUNDS=10
   MANAGEMENT_SESSION_SECRET=your-random-session-signing-secret
   ```

3. **Start the application**:
   - **Production mode**:
     ```bash
     npm start
     ```
   - **Development mode (with auto-reload)**:
     ```bash
     npm run dev
     ```

## 🔒 Security Services

VaultLink implements a defense-in-depth cryptographic foundation:

- **AES-256-GCM Encryption**: All secret payloads are encrypted using authenticated symmetric encryption (`aes-256-gcm`).
- **Unique Initialization Vectors (IV)**: Every secret receives a fresh, cryptographically secure 12-byte random IV.
- **Tamper Detection**: An AES-GCM 16-byte authentication tag guarantees ciphertext integrity and immediately rejects tampered or corrupted payloads.
- **Bcrypt Salted Hashing**: Passphrases, 6-digit access codes, and sender management tokens are hashed using `bcrypt` with adaptive salt rounds (`BCRYPT_SALT_ROUNDS`), never stored in plaintext.
- **SHA-256 Fingerprint**: A 12-character hex fingerprint provides a safe integrity reference for senders without exposing secret data.
- **Isolated Master Key**: The 32-byte master encryption key (`VAULT_MASTER_KEY`) resides exclusively in server environment variables and is never transmitted or saved to the database.

---

## 📡 API Reference: Create Secret Handover Room

### `POST /api/secrets`
Creates a zero-knowledge encrypted handover link with optional release scheduling and dual-factor verification.

#### Request Body
```json
{
  "secret": "sample-dummy-api-key-xyz-123456789",
  "ttl_seconds": 3600,
  "max_views": 1,
  "available_at": "2026-09-24T19:00:00.000Z",
  "passphrase": "CorrectHorseBatteryStaple!2026",
  "access_code": "849201"
}
```

| Field | Type | Required | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `secret` | String | **Yes** | 1 to 10,000 characters | The sensitive payload to encrypt. |
| `ttl_seconds` | Integer | **Yes** | 60 to 86,400 (1 min - 24 hrs) | Time-to-live before auto-expiration. |
| `max_views` | Integer | **Yes** | 1 to 5 | Maximum allowed view/reveal operations. |
| `passphrase` | String | **Yes** | 8 to 128 characters | Secret passphrase required for decryption. |
| `access_code` | String | **Yes** | Exactly 6 numeric digits (`^\d{6}$`) | Secondary verification code. |
| `available_at` | String (ISO) | No | Future timestamp | Optional scheduled availability timestamp. |

#### Response (`201 Created`)
```json
{
  "id": "2Qi2cXS-9o1BKRcGigdl8",
  "view_url": "http://localhost:3000/view/2Qi2cXS-9o1BKRcGigdl8",
  "manage_url": "http://localhost:3000/manage/2Qi2cXS-9o1BKRcGigdl8?token=oQ38v6B1iB4X-sample-mgmt-token",
  "expires_at": "2026-09-24T20:00:00.000Z",
  "available_at": "2026-09-24T19:00:00.000Z",
  "views_remaining": 1,
---

## 📡 API Reference: Verification & Access Control

### 1. `POST /api/secrets`
Creates a zero-knowledge encrypted handover room with optional release scheduling and dual-factor verification.

#### Request Body
```json
{
  "secret": "sample-dummy-api-key-xyz-123456789",
  "ttl_seconds": 3600,
  "max_views": 1,
  "available_at": "2026-09-24T19:00:00.000Z",
  "passphrase": "CorrectHorseBatteryStaple!2026",
  "access_code": "849201"
}
```

| Field | Type | Required | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `secret` | String | **Yes** | 1 to 10,000 characters | The sensitive payload to encrypt. |
| `ttl_seconds` | Integer | **Yes** | 60 to 86,400 (1 min - 24 hrs) | Time-to-live before auto-expiration. |
| `max_views` | Integer | **Yes** | 1 to 5 | Maximum allowed view/reveal operations. |
| `passphrase` | String | **Yes** | 8 to 128 characters | Secret passphrase required for decryption. |
| `access_code` | String | **Yes** | Exactly 6 numeric digits (`^\d{6}$`) | Secondary verification code. |
| `available_at` | String (ISO) | No | Future timestamp | Optional scheduled availability timestamp. |

#### Response (`201 Created`)
```json
{
  "id": "2Qi2cXS-9o1BKRcGigdl8",
  "view_url": "http://localhost:3000/view/2Qi2cXS-9o1BKRcGigdl8",
  "manage_url": "http://localhost:3000/manage/2Qi2cXS-9o1BKRcGigdl8?token=oQ38v6B1iB4X-sample-mgmt-token",
  "expires_at": "2026-09-24T20:00:00.000Z",
  "available_at": "2026-09-24T19:00:00.000Z",
  "views_remaining": 1,
  "status": "scheduled",
  "secret_fingerprint": "a3f5b9c1d0e2"
}
```

---

### 2. `POST /api/secrets/:id/verify`
Authenticates the 6-digit access code and passphrase against stored salted bcrypt hashes. Upon successful multi-factor verification, issues a temporary, single-use verification token valid for 120 seconds (2 minutes).

#### Request Body
```json
{
  "access_code": "849201",
  "passphrase": "CorrectHorseBatteryStaple!2026"
}
```

| Field | Type | Required | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `access_code` | String | **Yes** | Exactly 6 numeric digits (`^\d{6}$`) | Sender-provided 6-digit PIN. |
| `passphrase` | String | **Yes** | 1 to 128 characters | Sender-provided passphrase. |

#### Response (`200 OK`)
```json
{
  "verified": true,
  "verification_token": "j8X9qL2_M1p3wZv7R4yK9tN5sE6aB0cF1dG8hJ3kL5m",
  "expires_in_seconds": 120
}
```

#### Generic Failure Response (`400 Bad Request`)
```json
{
  "error": "Secure handover unavailable or verification failed."
}
```
> 🛡️ **Anti-Enumeration Guarantee:** The failure message and status code are identical whether the secret ID is invalid, expired, scheduled, revoked, burned, or if the access code or passphrase was incorrect.

#### Rate Limit Response (`429 Too Many Requests`)
```json
{
  "error": "Too many verification attempts. Please try again later."
}
```
- **Threshold**: Maximum 5 failed verification attempts per IP address and secret ID within a 10-minute sliding window.
- **Reset**: Successful verification clears the failed attempt counter for that IP and secret ID.

---

### 3. `POST /api/secrets/:id/reveal`
Atomically consumes a single-use verification token, executes atomic quota decrement and cryptographic payload shredding via Postgres RPC (`reveal_secret_atomically`), decrypts the secret in the Express backend, and dispatches the plaintext secret with a 15-second self-destruct directive.

#### Request Headers
```http
Content-Type: application/json
```

#### Request Body
```json
{
  "verification_token": "j8X9qL2_M1p3wZv7R4yK9tN5sE6aB0cF1dG8hJ3kL5m"
}
```

#### Response (`200 OK`)
```json
{
  "secret": "sample-production-api-key-xyz",
  "views_remaining": 0,
  "burned": true,
  "display_seconds": 15
}
```

#### Generic Failure Response (`404 Not Found`)
```json
{
  "error": "Secret not found, expired, or already destroyed."
}
```

---

## ⚡ Concurrency & Race Condition Protection

To prevent concurrent race conditions (e.g., 20 parallel reveal requests arriving simultaneously for a `max_views = 1` secret), VaultLink enforces database engine-level atomic serialization via the `reveal_secret_atomically` PostgreSQL stored procedure:

1. **`FOR UPDATE` Row Locks**: Row locks are acquired immediately on the matching `verification_tokens` and `secrets` records.
2. **Single-Use Verification Token**: The token's `used_at` timestamp is set atomically within the transaction. Subsequent requests presenting the same token hash are rejected immediately (`404`).
3. **Strict Quota & State Evaluation**: If `views_remaining <= 0`, status is not `active`, or current time is past `expires_at`, the transaction aborts and returns an empty record set (`404`).
4. **Immediate Cryptographic Shredding**: When `views_remaining` reaches 0, the database immediately nullifies `ciphertext`, `iv`, `auth_tag`, `passphrase_hash`, and `access_code_hash`, transitions status to `burned`, and sets `revealed_at`.
5. **Exact 1-in-20 Guarantee**: Out of 20 concurrent parallel reveal requests, **exactly 1** receives HTTP 200 with the decrypted secret, and **exactly 19** receive HTTP 404.

---

## 🛡️ Scraper Shield

Chat applications and messaging platforms (such as Slack, Discord, WhatsApp, Twitter/X, Facebook, LinkedIn, and Telegram) automatically dispatch automated crawlers to preview shared links. If simply navigating to a URL were to decrypt, consume, decrement, or expire a secret, link-preview crawlers would prematurely destroy one-time secrets before the intended human recipient could open them.

To prevent premature destruction and link preview leakage:
- **Crawler & Link-Preview Detection**: VaultLink intercepts common crawler and link-preview User-Agent signatures (such as `Slackbot`, `Discordbot`, `WhatsApp`, `Twitterbot`, `facebookexternalhit`, `LinkedInBot`, `TelegramBot`, `crawl`, `spider`, `bot`) case-insensitively.
- **Generic Preview Response**: Detected preview bots receive a safe, generic HTTP 200 verification notice with no secret ID, expiry, view quota, status, or cryptographic metadata.
- **Zero Database Querying or Logging on Bot Hits**: Crawler requests bypass database secret queries entirely, performing no database reads, writes, or audit event inserts.
- **Read-Only Invariant on `GET /view/:id`**: Navigating to `GET /view/:id` is strictly read-only and **never** decrypts, reveals, consumes, decrements, expires, revokes, or deletes a secret.
- **Verified Reveal Boundary**: Secrets are revealed strictly through a subsequent verified `POST` transaction.

---

## 🎛️ Sender Management Dashboard & Panic Burn

VaultLink provides senders with an isolated, zero-knowledge management interface to monitor secret telemetry in real-time and revoke active or scheduled handovers instantly:

### 1. Ephemeral 15-Minute Signed Management Sessions
- **Single-Use Token Exchange**: Senders receive a private URL: `/manage/:id?token=raw-management-token`.
- **Query Parameter Scrubbing & Referrer Stripping**: When accessed, the server verifies the raw token against `management_token_hash` in Supabase using bcrypt. Upon verification, the server issues a cryptographically signed HMAC-SHA256 session token into an `HttpOnly`, `SameSite=Strict`, `Path=/` cookie valid for 15 minutes, accompanied by `Referrer-Policy: no-referrer`, and issues an immediate HTTP 302 redirect to clean `/manage/:id`.
- **URL & Log Sanitization**: Because of the 302 redirect, the raw management token is instantly purged from the browser address bar, navigation history, access logs, and outbound referrers.
- **Strict Tenant Isolation**: Management sessions are cryptographically bound to `secret_id` and verified using `crypto.timingSafeEqual`. A valid session for secret A cannot view or manage secret B.

### 2. Zero-Knowledge Telemetry & Activity Timeline
- **Safe Metadata Only**: The dashboard displays safe status badges (`active`, `scheduled`, `revealed`, `burned`, `expired`, `revoked`), creation timestamp, unlock timestamp, expiration time, view quota, and remaining views.
- **Zero Plaintext & Hash Exposure**: The dashboard never displays the secret plaintext, encryption keys, ciphertext, IV, auth tag, passphrase, access code, or any hashes.
- **Safe Audit Timeline**: Renders chronological event logs (`created`, `activated`, `verification_passed`, `verification_failed`, `revealed`, `expired`, `panic_burned`) with human-readable timestamps and event summaries.

### 3. Atomic Panic Burn (`POST /api/secrets/:id/panic-burn`)
- **Emergency Revocation**: If a sender suspects link compromise, misdelivery, or credential obsolescence, they can trigger **Panic Burn Secret** directly from the dashboard.
- **Confirmation Safeguard**: A double-confirmation modal prevents accidental revocations.
- **CSRF Protection**: All burn requests require an anti-CSRF token generated with the session and supplied via `X-CSRF-Token` header or request body.
- **Atomic Database Shredding**: Invokes Postgres stored procedure `panic_burn_secret_atomically(p_secret_id, p_now)` with row-level locking (`FOR UPDATE`).
- **Immediate Cryptographic Obliteration**:
  - Nullifies `ciphertext = NULL`, `iv = NULL`, `auth_tag = NULL`, `passphrase_hash = NULL`, and `access_code_hash = NULL`.
  - Sets `status = 'revoked'` and `revoked_at = NOW()`.
  - Retains non-sensitive metadata and `management_token_hash` for sender audit review.
  - Appends a `panic_burned` audit event to `secret_events`.
- **Immediate Recipient Invalidation**: The recipient link `/view/:id` immediately switches to the generic unavailable landing page. Subsequent verification or reveal requests return generic failure responses.
- **Scraper & Bot Shielding**: Bot User-Agents attempting to trigger panic burn are immediately rejected.

---

## 📬 Recipient Receipt Acknowledgement

VaultLink enables recipients to provide cryptographic proof of receipt without compromising their privacy or revealing identifying information:

### 1. Recipient Acknowledgement Flow
- **Single-Use Ephemeral Token**: Upon successful decryption during `POST /api/secrets/:id/reveal`, the backend generates a cryptographically random 32-byte URL-safe acknowledgement token, computes its SHA-256 hash, persists only the hash with a 15-minute TTL into `acknowledgement_tokens`, and returns the raw token in the reveal JSON response.
- **In-Memory Confinement**: The recipient's browser holds the token strictly in a local JavaScript closure. The raw token is **never** written to `localStorage`, `sessionStorage`, cookies, query parameters, or browser history.
- **Receipt Confirmation**: The recipient checks *"I have copied and understood this secure handover."* and clicks **Acknowledge Receipt**, dispatching `POST /api/secrets/:id/acknowledge`.
- **Atomic Database Execution**: Postgres stored procedure `acknowledge_secret_atomically(p_secret_id, p_token_hash, p_now)` acquires a row lock (`FOR UPDATE`), confirms token validity, marks `used_at = NOW()`, sets `secrets.acknowledged_at = NOW()`, and preserves existing secret status (`burned` remains burned).
- **Safe Audit Logging**: Records an `acknowledged` event in `secret_events` with metadata `{ "source": "recipient_acknowledgement" }`.

### 2. Privacy-Preserving Acknowledgement Design
Acknowledgement is strictly zero-knowledge and privacy-preserving:
- **Zero Plaintext / Credential Storage**: Never records the plaintext secret, copied text, passphrase, access code, or cryptographic keys.
- **Zero Recipient Profiling**: Never stores recipient names, messages, email addresses, IP addresses, user agents, or browser fingerprints.
- **Strictly Optional & Anonymous**: Recipients are not required to acknowledge; if skipped or if the tab is closed, the handover remains burned and secure without exposing recipient telemetry.

### 3. 15-Minute Window & Independent Lifecycles
- **Decoupled From Display Timer**: The 15-second display timer solely controls how long the decrypted plaintext stays in the browser DOM. When 15 seconds elapse, the secret is permanently wiped and removed from the page, but the acknowledgement card remains active for up to 15 minutes.
- **Window Expiry**: If the 15-minute window passes without acknowledgement, the token expires, controls are disabled, and subsequent attempts return generic HTTP 404.

### 4. Sender Dashboard Synchronization
The sender management dashboard automatically renders a dedicated Recipient Acknowledgement card:
- **Confirmed**: *"Acknowledged at: [timestamp]"* with a green confirmed badge.
- **Pending**: *"Acknowledgement pending"* when revealed but unconfirmed.
- **Not Applicable**: *"Not applicable until reveal"* when secret has not yet been unlocked.
- **Timeline**: An `Acknowledged` event item appears in the Safe Activity Timeline.

---

## 🧪 Testing & Verification

### Automated Test Suite:
Run the complete automated backend, recipient view, verification, cryptographic, lifecycle sweeper, dashboard, panic burn, and acknowledgement test suite powered by Node.js built-in test runner:

```bash
npm test
```

### URLs to Test:
- **Sender Home Page**: [http://localhost:3000](http://localhost:3000/)
- **Recipient Landing Page**: [http://localhost:3000/view/:id](http://localhost:3000/view/:id)
- **Sender Management Dashboard Entry**: [http://localhost:3000/manage/:id?token=raw-token](http://localhost:3000/manage/:id?token=raw-token)
- **Clean Sender Management Dashboard**: [http://localhost:3000/manage/:id](http://localhost:3000/manage/:id)
- **Health Check Endpoint**: [http://localhost:3000/health](http://localhost:3000/health)
  - Returns: `{"status":"ok","app":"VaultLink Secure Handover Room"}`
- **Database Status Endpoint**: [http://localhost:3000/api/database-status](http://localhost:3000/api/database-status)
  - Returns: `{"status":"connected","database":"supabase"}`
- **Create Secret Endpoint**: `POST http://localhost:3000/api/secrets`
- **Verify Secret Endpoint**: `POST http://localhost:3000/api/secrets/:id/verify`
- **Reveal Secret Endpoint**: `POST http://localhost:3000/api/secrets/:id/reveal`
- **Panic Burn Endpoint**: `POST http://localhost:3000/api/secrets/:id/panic-burn`
- **Acknowledge Receipt Endpoint**: `POST http://localhost:3000/api/secrets/:id/acknowledge`

---

## 📋 Frontend Testing Checklist

Follow this manual checklist on the web interface ([http://localhost:3000](http://localhost:3000/)) to verify zero-knowledge sender and recipient workflows:

1. **Create an Active Handover**:
   - Enter secret text, pick an expiry window (e.g. 1 hour), select max views (e.g. 1 view), enter 6-digit access code (e.g. `849201`), enter passphrase (e.g. `SecretPassword!99`), and click **Generate Secure Link**.
   - Verify that the form transitions to the **Secure Handover Created** success panel showing `Active Now` badge, recipient view link, management link, and generated QR code.
2. **Create a Scheduled Handover**:
   - Check **Schedule this handover**, pick a future date & time, fill in required fields, and submit.
   - Verify that the success panel displays a `Scheduled` status badge with the scheduled unlock timestamp.
3. **Verify Recipient Active View**:
   - Open the generated `http://localhost:3000/view/:id` in a browser.
   - Enter valid 6-digit access code and passphrase and click **Verify Secure Handover**.
   - Confirm immediate transition to green verified state: *"Identity verified. You may now reveal and destroy the secret."* with the **Reveal & Destroy Secret** action button.
4. **Reveal & 15-Second Self-Destruction**:
   - Click **Reveal & Destroy Secret**.
   - Confirm secret plaintext is decrypted and displayed with a 15-second live countdown timer and animated visual progress bar.
   - Click **Copy Secret** and verify clipboard feedback (*"✓ Copied securely"*).
   - Once 15 seconds expire, verify that the textarea is permanently wiped and removed from the DOM, and the UI transitions to *"Secret Destroyed - This secret has been permanently destroyed."*
5. **Recipient Acknowledgement**:
   - In the reveal screen, select the checkbox: *"I have copied and understood this secure handover."*
   - Verify the **Acknowledge Receipt** button becomes enabled. Click it.
   - Verify immediate transition to *"Receipt acknowledged. The sender has been notified."* and controls become disabled.
   - Confirm that acknowledgement remains possible even after the 15-second secret display timer ends, up until the 15-minute token expiry.
6. **Sender Dashboard Synchronization**:
   - Open the sender management link in another tab (`http://localhost:3000/manage/:id?token=...`).
   - Confirm clean redirect to `/manage/:id`.
   - Verify that the **Recipient acknowledgement** card shows *"Confirmed"* and displays *"Acknowledged at: [timestamp]"*.
   - Verify that the safe activity timeline includes an `Acknowledged` event with a UTC timestamp.
7. **Test Anti-Replay & Concurrency**:
   - Refresh the recipient page or attempt to reveal/acknowledge again; confirm generic unavailable/destroyed page.
8. **Test Verification Failure & Rate Limiting**:
   - Enter an incorrect access code or passphrase. Confirm generic error *"Verification failed. Please check your secure handover details."*
   - Repeat 5 times. On attempt 6, confirm rate-limit error *"Too many attempts. Please wait before trying again."*
9. **Sender Management Dashboard & Panic Burn**:
   - On an active or scheduled secret, click **Panic Burn Secret**, review the confirmation modal warning, and confirm the action.
   - Verify that the dashboard transitions to `Revoked / Burned` state and records the `panic_burned` event.
   - In another browser tab, attempt to access `http://localhost:3000/view/:id` and confirm that it immediately renders the generic `Secure Handover Unavailable` page.

---

## ⏰ Scheduled Delivery and TTL Cleanup

VaultLink automates secret state transitions without requiring manual human requests or client interaction:

- **15-Second Automated Background Sweeper**: A periodic server-side daemon runs immediately upon server initialization and continuously every 15 seconds.
- **Scheduled Secrets Activate at `available_at`**: When server time reaches or passes `available_at`, scheduled secrets are atomically transitioned to `active`. Their encrypted material remains intact and becomes accessible for verification.
- **Immediate Expiry Cleanup**: As soon as `expires_at` is reached or passed, the database stored procedure (`maintain_secret_lifecycle`) shreds all sensitive payload components: `ciphertext = NULL`, `iv = NULL`, `auth_tag = NULL`, `passphrase_hash = NULL`, and `access_code_hash = NULL`. The status transitions to `expired`.
- **Generic Unavailable Shield**: Expired, revoked, and burned links return identical generic unavailable notices to prevent state enumeration.
- **Authoritative Server & Database Time**: Client devices may have skewed or manipulated local system clocks. VaultLink exclusively relies on authoritative server-side UTC timestamps and Postgres atomic row evaluations.

---

## 🎪 Presentation Demo Mode (Step 12)

VaultLink includes a safe, local **Presentation Demo Mode** designed for project reviews, live demonstrations, and evaluators to showcase the end-to-end zero-knowledge security journey without ever handling or risking real credentials.

### Strict Security Boundaries
- **Disabled by Default**: Demo Mode requires `DEMO_MODE_ENABLED=true` in `.env`.
- **Production Air-Gap**: Demo Mode is hard-coded to refuse execution if `NODE_ENV=production`, even if `DEMO_MODE_ENABLED=true` is set.
- **Genuine Cryptography**: The demo does NOT use dummy mock tables or insecure bypasses. It runs against the real AES-256-GCM encryption engine, genuine Argon2id/bcrypt hashing, real Supabase storage, real lifecycle sweeper, and atomic PostgreSQL stored procedures.
- **Synthetic Data Tagging**: All demo data is strictly tagged with fake credentials (`DEMO_API_KEY_NOT_REAL`, access code `123456`, passphrase `demo-vault`) and marked with `{ demo: true }` in audit logs.
- **Zero Real-Secret Cross-Talk**: Demo endpoints reject real secret IDs with HTTP 404.

### Enabling Demo Mode Locally
1. In `.env`, set:
   ```env
   DEMO_MODE_ENABLED=true
   ```
2. Start or restart the local server:
   ```bash
   npm start
   ```
3. Open `http://localhost:3000`. The **Presentation Demo Mode** card will automatically appear below the main handover creation form.

### 7-Step Demonstration Sequence
1. **Launch Demo Scenario**: Click the **Launch Demo Scenario** button. A fresh one-time handover is encrypted and stored in Supabase with a 120s TTL and 1 view allowance. The demo credentials and links are immediately displayed.
2. **Visual Security Journey**: The interactive timeline illuminates Step 1 (*Handover Created*) and Step 2 (*Safe Metadata Stored*), updating live every 3 seconds via `/api/demo/:id/timeline`.
3. **Simulate Crawler Visit**: Click **Simulate Crawler Visit**. The system dispatches a request with `User-Agent: Slackbot-LinkExpanding 1.0` to the recipient link. Step 3 is completed, displaying: *"Bot blocked - secret remains protected"*, proving scrapers cannot trigger secret reveals or decrement view counts.
4. **Open Recipient View**: Click **Test Recipient View** to open `/view/:id` in a new tab. Enter access code `123456` and passphrase `demo-vault`. Multi-factor verification succeeds and an in-memory verification token is created. Step 4 and 5 complete.
5. **Reveal Plaintext**: Click **Reveal Secret Handover**. The one-time atomic stored procedure executes, returning the plaintext payload and shredding all ciphertext, IV, and auth tag from the database. Step 6 and Step 8 complete.
6. **Confirm Recipient Acknowledgement**: Click **Acknowledge Secure Receipt**. The safe receipt confirmation is recorded. Step 7 completes.
7. **Run Concurrency Race-Condition Test**: Return to the demo panel and click **Run Concurrency Test**. The server fires 20 simultaneous verified reveal requests in parallel against a temporary 1-view secret. The test returns aggregate confirmation: `20 parallel requests: 1 revealed, 19 blocked.`

---

## 📂 Final Folder Structure

```
vaultlink/
├── database/
│   └── README.md
├── src/
│   ├── routes/
│   │   ├── demoRoutes.js
│   │   ├── manageRoutes.js
│   │   ├── secretRoutes.js
│   │   └── viewRoutes.js
│   ├── services/
│   │   ├── cryptoService.js
│   │   ├── demoService.js
│   │   ├── hashService.js
│   │   ├── lifecycleSweeperService.js
│   │   ├── managementSessionService.js
│   │   ├── supabaseService.js
│   │   └── verificationRateLimitService.js
│   ├── views/
│   │   └── viewTemplates.js
│   ├── middleware/
│   └── server.js
├── public/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   ├── app.js
│   │   ├── manage.js
│   │   ├── qrcode.js
│   │   └── view.js
│   └── index.html
├── tests/
│   ├── acknowledgement.test.js
│   ├── api.test.js
│   ├── createSecret.test.js
│   ├── cryptoService.test.js
│   ├── demoMode.test.js
│   ├── hashService.test.js
│   ├── lifecycleSweeper.test.js
│   ├── managementDashboard.test.js
│   ├── panicBurn.test.js
│   ├── revealSecret.test.js
│   ├── verifySecret.test.js
│   └── viewRoutes.test.js
├── supabase-schema.sql
├── package.json
├── .env.example
├── .gitignore
└── README.md
```



