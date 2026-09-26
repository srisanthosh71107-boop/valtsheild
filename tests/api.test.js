const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');

const PORT = 3099;

function makeRequest(path) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:${PORT}${path}`, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: data ? (res.headers['content-type']?.includes('application/json') ? JSON.parse(data) : data) : null
          });
        } catch (e) {
          resolve({ statusCode: res.statusCode, headers: res.headers, body: data });
        }
      });
    }).on('error', reject);
  });
}

describe('Foundation API Verification', () => {
  let server;

  before(() => {
    server = app.listen(PORT);
  });

  after(() => {
    server.close();
  });

  test('1. GET / serves home page successfully', async () => {
    const homeRes = await makeRequest('/');
    assert.equal(homeRes.statusCode, 200);
    assert.equal(typeof homeRes.body, 'string');
    assert.ok(homeRes.body.includes('VaultLink'));
  });

  test('2. GET /health returns status ok', async () => {
    const healthRes = await makeRequest('/health');
    assert.equal(healthRes.statusCode, 200);
    assert.equal(healthRes.body.status, 'ok');
    assert.equal(healthRes.body.app, 'VaultLink Secure Handover Room');
  });

  test('3. GET /api/database-status returns connected', async () => {
    const dbRes = await makeRequest('/api/database-status');
    assert.equal(dbRes.statusCode, 200);
    assert.equal(dbRes.body.status, 'connected');
    assert.equal(dbRes.body.database, 'supabase');
  });
});

