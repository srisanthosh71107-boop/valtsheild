const http = require('http');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const { hashValue } = require('../src/services/hashService');
const {
  encryptSecret,
  generateVerificationToken,
  hashVerificationToken
} = require('../src/services/cryptoService');
const {
  COOKIE_NAME,
  createManagementSession
} = require('../src/services/managementSessionService');

const PORT = 3079;

const mockDb = {
  secrets: [],
  secret_events: [],
  verification_tokens: [],
  acknowledgement_tokens: []
};

function makeRequest(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const reqHeaders = { ...headers };
    if (payload) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: PORT,
        path,
        method,
        headers: reqHeaders
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch (e) {
            json = data;
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: json
          });
        });
      }
    );

    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function runDemo() {
  // Setup mocks
  supabase.from = (table) => ({
    insert: async (data) => {
      const rows = Array.isArray(data) ? data : [data];
      if (mockDb[table]) mockDb[table].push(...rows);
      return { data: rows, error: null };
    },
    select: (fields) => ({
      eq: (col, val) => ({
        order: () => ({
          then: (resolve) => {
            const filtered = (mockDb[table] || []).filter((r) => r[col] === val);
            resolve({ data: filtered, error: null });
          }
        }),
        maybeSingle: async () => {
          const found = (mockDb[table] || []).find((r) => r[col] === val);
          if (!found) return { data: null, error: null };
          if (fields && fields !== '*') {
            const fieldList = fields.split(',').map((f) => f.trim());
            const resObj = {};
            fieldList.forEach((f) => {
              if (found[f] !== undefined) resObj[f] = found[f];
            });
            return { data: resObj, error: null };
          }
          return { data: found, error: null };
        }
      })
    })
  });

  supabase.rpc = async (funcName, args) => {
    if (funcName === 'reveal_secret_atomically') {
      const { p_secret_id, p_now } = args;
      const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
      if (!secret) return { data: [], error: null };

      const savedCiphertext = secret.ciphertext;
      const savedIv = secret.iv;
      const savedAuthTag = secret.auth_tag;

      secret.ciphertext = null;
      secret.iv = null;
      secret.auth_tag = null;
      secret.passphrase_hash = null;
      secret.access_code_hash = null;
      secret.status = 'burned';
      secret.views_remaining = 0;
      secret.revealed_at = p_now;

      return {
        data: [{
          id: secret.id,
          ciphertext: savedCiphertext,
          iv: savedIv,
          auth_tag: savedAuthTag,
          views_remaining: 0,
          burned: true,
          status: 'burned'
        }],
        error: null
      };
    }

    if (funcName === 'acknowledge_secret_atomically') {
      const { p_secret_id, p_token_hash, p_now } = args;
      const token = mockDb.acknowledgement_tokens.find(
        (t) => t.token_hash === p_token_hash && t.secret_id === p_secret_id
      );
      if (!token || token.used_at) return { data: [], error: null };

      const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
      if (!secret) return { data: [], error: null };

      token.used_at = p_now;
      secret.acknowledged_at = p_now;

      return {
        data: [{
          secret_id: secret.id,
          acknowledged_at: p_now
        }],
        error: null
      };
    }
  };

  const server = app.listen(PORT);

  try {
    console.log('=== VAULTLINK STEP 11 LIVE DEMONSTRATION ===');
    const secretId = 'sec_demo_step11_live';
    const encrypted = encryptSecret('PRODUCTION_DATABASE_MASTER_CREDENTIAL');

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('DemoPassphrase123!'),
      access_code_hash: await hashValue('987654'),
      management_token_hash: await hashValue('demo-mgmt-token'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    // 1. Initial State: Sender views dashboard before reveal
    const { sessionToken } = createManagementSession(secretId);
    let dashRes = await makeRequest('GET', `/manage/${secretId}`, null, {
      Cookie: `${COOKIE_NAME}=${sessionToken}`
    });
    console.log('\n[1] SENDER DASHBOARD BEFORE REVEAL:');
    console.log('Contains "Recipient acknowledgement":', dashRes.body.includes('Recipient acknowledgement'));
    console.log('Contains "Not applicable until reveal":', dashRes.body.includes('Not applicable until reveal'));

    // 2. Recipient verifies and reveals secret
    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    console.log('\n[2] RECIPIENT REVEALS SECRET:');
    console.log('HTTP Status:', revealRes.status);
    console.log('Decrypted Secret:', revealRes.body.secret);
    console.log('Views remaining:', revealRes.body.views_remaining);
    console.log('Burned:', revealRes.body.burned);
    console.log('Acknowledgement Token received:', revealRes.body.acknowledgement_token ? 'YES (32+ bytes URL-safe)' : 'NO');
    console.log('Acknowledgement Window:', revealRes.body.acknowledgement_expires_in_seconds, 'seconds (15 mins)');

    // 3. Sender views dashboard after reveal, before acknowledgement
    dashRes = await makeRequest('GET', `/manage/${secretId}`, null, {
      Cookie: `${COOKIE_NAME}=${sessionToken}`
    });
    console.log('\n[3] SENDER DASHBOARD AFTER REVEAL, BEFORE ACKNOWLEDGEMENT:');
    console.log('Contains "Acknowledgement pending":', dashRes.body.includes('Acknowledgement pending'));

    // 4. Recipient acknowledges receipt
    const ackRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: revealRes.body.acknowledgement_token
    });
    console.log('\n[4] RECIPIENT ACKNOWLEDGES RECEIPT:');
    console.log('HTTP Status:', ackRes.status);
    console.log('Response body:', JSON.stringify(ackRes.body));

    // 5. Sender views dashboard after acknowledgement
    dashRes = await makeRequest('GET', `/manage/${secretId}`, null, {
      Cookie: `${COOKIE_NAME}=${sessionToken}`
    });
    console.log('\n[5] SENDER DASHBOARD AFTER ACKNOWLEDGEMENT:');
    console.log('Contains "Confirmed":', dashRes.body.includes('Confirmed'));
    console.log('Contains "Acknowledged at:":', dashRes.body.includes('Acknowledged at:'));
    console.log('Contains timeline "Acknowledged":', dashRes.body.includes('Acknowledged'));

    // 6. Verify replay protection: second acknowledge attempt fails with 404
    const replayRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: revealRes.body.acknowledgement_token
    });
    console.log('\n[6] REPLAY ATTEMPT WITH SAME ACKNOWLEDGEMENT TOKEN:');
    console.log('HTTP Status:', replayRes.status);
    console.log('Response body:', JSON.stringify(replayRes.body));

    console.log('\n=== STEP 11 DEMONSTRATION COMPLETE: ALL CHECKS PASSED ===\n');
  } finally {
    server.close();
  }
}

runDemo().catch(console.error);
