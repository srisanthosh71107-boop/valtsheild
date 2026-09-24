const {
  encryptSecret
} = require('../src/services/cryptoService');
const {
  runLifecycleMaintenance
} = require('../src/services/lifecycleSweeperService');
const supabase = require('../src/services/supabaseService');

async function demonstrate() {
  console.log('=== VAULTLINK STEP 9: LIFECYCLE AUTOMATION DEMONSTRATION ===\n');

  // Set up mock DB to demonstrate RPC behavior
  const mockDb = {
    secrets: [],
    secret_events: []
  };

  // Mock Supabase
  supabase.from = (table) => ({
    insert: async (data) => {
      mockDb[table].push(...(Array.isArray(data) ? data : [data]));
      return { data, error: null };
    },
    select: () => ({
      eq: (c1, v1) => ({
        eq: (c2, v2) => ({
          limit: async () => ({
            data: mockDb[table].filter((r) => r[c1] === v1 && r[c2] === v2),
            error: null
          })
        })
      })
    })
  });

  supabase.rpc = async (fn, { p_now }) => {
    const nowTime = new Date(p_now).getTime();
    const activatedIds = [];
    const expiredIds = [];

    // 1. Activate
    mockDb.secrets.forEach((s) => {
      if (
        s.status === 'scheduled' &&
        new Date(s.available_at).getTime() <= nowTime &&
        new Date(s.expires_at).getTime() > nowTime
      ) {
        s.status = 'active';
        activatedIds.push(s.id);
      }
    });

    // 2. Expire
    mockDb.secrets.forEach((s) => {
      if (
        (s.status === 'scheduled' || s.status === 'active') &&
        new Date(s.expires_at).getTime() <= nowTime
      ) {
        s.ciphertext = null;
        s.iv = null;
        s.auth_tag = null;
        s.passphrase_hash = null;
        s.access_code_hash = null;
        s.status = 'expired';
        expiredIds.push(s.id);
      }
    });

    return {
      data: {
        activated_ids: activatedIds,
        expired_ids: expiredIds
      },
      error: null
    };
  };

  // -------------------------------------------------------------
  // Demonstration 1: Scheduled Secret Becoming Active
  // -------------------------------------------------------------
  console.log('--- Demonstration 1: Scheduled Secret Reaching available_at ---');
  const scheduledSecret = {
    id: 'demo_scheduled_secret_101',
    ciphertext: 'U2FsdGVkX1+demoCiphertext12345==',
    iv: 'randomIv12Bytes==',
    auth_tag: 'authTag16Bytes==',
    passphrase_hash: '$2b$12$demoPassHash',
    access_code_hash: '$2b$12$demoCodeHash',
    management_token_hash: '$2b$12$demoMgmtHash',
    available_at: new Date(Date.now() - 5000).toISOString(), // 5 seconds in the past
    expires_at: new Date(Date.now() + 3600000).toISOString(), // 1 hour in the future
    status: 'scheduled'
  };
  mockDb.secrets.push(scheduledSecret);

  console.log('Before sweep:');
  console.log('  ID:          ', scheduledSecret.id);
  console.log('  Status:      ', scheduledSecret.status);
  console.log('  Ciphertext:  ', scheduledSecret.ciphertext);

  const sweep1Result = await runLifecycleMaintenance();

  console.log('\nAfter sweep at available_at:');
  console.log('  Activated IDs:', sweep1Result.activated_ids);
  console.log('  Status:       ', scheduledSecret.status);
  console.log('  Ciphertext:   ', scheduledSecret.ciphertext, '(Intact)');
  console.log('  Audit Events: ', mockDb.secret_events.filter(e => e.secret_id === scheduledSecret.id));

  // -------------------------------------------------------------
  // Demonstration 2: Secret Reaching expires_at and Data Shredded
  // -------------------------------------------------------------
  console.log('\n--- Demonstration 2: Active Secret Reaching expires_at ---');
  const activeExpiringSecret = {
    id: 'demo_expiring_secret_202',
    ciphertext: 'U2FsdGVkX1+sensitiveProductionKey==',
    iv: 'productionIv12==',
    auth_tag: 'productionTag16==',
    passphrase_hash: '$2b$12$secretPassHash',
    access_code_hash: '$2b$12$secretCodeHash',
    management_token_hash: '$2b$12$secretMgmtHash',
    available_at: new Date(Date.now() - 60000).toISOString(),
    expires_at: new Date(Date.now() - 1000).toISOString(), // Expired 1 second ago
    status: 'active'
  };
  mockDb.secrets.push(activeExpiringSecret);

  console.log('Before sweep:');
  console.log('  ID:          ', activeExpiringSecret.id);
  console.log('  Status:      ', activeExpiringSecret.status);
  console.log('  Ciphertext:  ', activeExpiringSecret.ciphertext);
  console.log('  IV:          ', activeExpiringSecret.iv);
  console.log('  Auth Tag:    ', activeExpiringSecret.auth_tag);
  console.log('  Pass Hash:   ', activeExpiringSecret.passphrase_hash);
  console.log('  Access Hash: ', activeExpiringSecret.access_code_hash);
  console.log('  Mgmt Hash:   ', activeExpiringSecret.management_token_hash);

  const sweep2Result = await runLifecycleMaintenance();

  console.log('\nAfter sweep at expires_at:');
  console.log('  Expired IDs:  ', sweep2Result.expired_ids);
  console.log('  Status:       ', activeExpiringSecret.status);
  console.log('  Ciphertext:   ', activeExpiringSecret.ciphertext, '(Shredded / NULL)');
  console.log('  IV:           ', activeExpiringSecret.iv, '(Shredded / NULL)');
  console.log('  Auth Tag:     ', activeExpiringSecret.auth_tag, '(Shredded / NULL)');
  console.log('  Pass Hash:    ', activeExpiringSecret.passphrase_hash, '(Shredded / NULL)');
  console.log('  Access Hash:  ', activeExpiringSecret.access_code_hash, '(Shredded / NULL)');
  console.log('  Mgmt Hash:    ', activeExpiringSecret.management_token_hash, '(Preserved)');
  console.log('  Audit Events: ', mockDb.secret_events.filter(e => e.secret_id === activeExpiringSecret.id));
}

demonstrate().catch(console.error);
