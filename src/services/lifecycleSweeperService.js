const supabase = require('./supabaseService');

let sweeperInterval = null;
let isSweepInProgress = false;

/**
 * Runs a single cycle of secret lifecycle maintenance:
 * 1. Calls maintain_secret_lifecycle RPC on Supabase.
 * 2. Emits safe audit events for newly activated and expired secrets.
 * 
 * @param {Date} [customNow] Optional date for testing or time-travel.
 * @returns {Promise<{ activated_ids: string[], expired_ids: string[] }>}
 */
async function runLifecycleMaintenance(customNow = null) {
  if (isSweepInProgress) {
    return { activated_ids: [], expired_ids: [] };
  }

  isSweepInProgress = true;
  const now = customNow instanceof Date ? customNow : new Date();
  const nowIso = now.toISOString();

  try {
    if (!supabase) {
      return { activated_ids: [], expired_ids: [] };
    }

    // Call atomic lifecycle RPC
    const { data: result, error: rpcError } = await supabase.rpc('maintain_secret_lifecycle', {
      p_now: nowIso
    });

    if (rpcError) {
      console.error('[LIFECYCLE] Maintenance sweep execution error.');
      return { activated_ids: [], expired_ids: [] };
    }

    // Parse activated and expired IDs
    let activatedIds = [];
    let expiredIds = [];

    if (result) {
      if (Array.isArray(result)) {
        // Table or array format fallback
        if (result.length > 0 && (result[0].activated_ids || result[0].expired_ids)) {
          activatedIds = Array.isArray(result[0].activated_ids) ? result[0].activated_ids : [];
          expiredIds = Array.isArray(result[0].expired_ids) ? result[0].expired_ids : [];
        } else if (result.length > 0 && result[0].action) {
          result.forEach((row) => {
            if (row.action === 'activated') activatedIds.push(row.secret_id);
            if (row.action === 'expired') expiredIds.push(row.secret_id);
          });
        }
      } else if (typeof result === 'object') {
        activatedIds = Array.isArray(result.activated_ids) ? result.activated_ids : [];
        expiredIds = Array.isArray(result.expired_ids) ? result.expired_ids : [];
      }
    }

    // Log safe operational summary in development if any changes occurred
    if (activatedIds.length > 0 || expiredIds.length > 0) {
      console.log(`Lifecycle maintenance: ${activatedIds.length} activated, ${expiredIds.length} expired`);
    }

    // Record safe audit events for activated secrets (ensuring no duplicates)
    for (const secretId of activatedIds) {
      try {
        const { data: existingEvents } = await supabase
          .from('secret_events')
          .select('id')
          .eq('secret_id', secretId)
          .eq('event_type', 'activated');

        if (!existingEvents || existingEvents.length === 0) {
          await supabase.from('secret_events').insert({
            secret_id: secretId,
            event_type: 'activated',
            created_at: nowIso,
            metadata: {
              source: 'background_sweeper'
            }
          });
        }
      } catch (err) {
        // Continue processing other events safely
      }
    }

    // Record safe audit events for expired secrets (ensuring no duplicates)
    for (const secretId of expiredIds) {
      try {
        const { data: existingEvents } = await supabase
          .from('secret_events')
          .select('id')
          .eq('secret_id', secretId)
          .eq('event_type', 'expired');

        if (!existingEvents || existingEvents.length === 0) {
          await supabase.from('secret_events').insert({
            secret_id: secretId,
            event_type: 'expired',
            created_at: nowIso,
            metadata: {
              source: 'background_sweeper'
            }
          });
        }
      } catch (err) {
        // Continue processing other events safely
      }
    }

    return {
      activated_ids: activatedIds,
      expired_ids: expiredIds
    };
  } catch (err) {
    console.error('[LIFECYCLE] Error running maintenance sweep.');
    return { activated_ids: [], expired_ids: [] };
  } finally {
    isSweepInProgress = false;
  }
}

/**
 * Starts the periodic 15-second background sweeper interval.
 * Guaranteed to never start duplicate intervals.
 * 
 * @returns {NodeJS.Timeout} The active interval timer
 */
function startLifecycleSweeper() {
  if (sweeperInterval) {
    return sweeperInterval;
  }

  // Run once immediately on startup
  runLifecycleMaintenance().catch(() => {});

  // Then run every 15 seconds
  sweeperInterval = setInterval(() => {
    runLifecycleMaintenance().catch(() => {});
  }, 15000);

  // Unref timer so it doesn't block process termination during tests
  if (sweeperInterval && typeof sweeperInterval.unref === 'function') {
    sweeperInterval.unref();
  }

  return sweeperInterval;
}

/**
 * Stops the background sweeper interval (used during tests).
 */
function stopLifecycleSweeperForTests() {
  if (sweeperInterval) {
    clearInterval(sweeperInterval);
    sweeperInterval = null;
  }
  isSweepInProgress = false;
}

module.exports = {
  startLifecycleSweeper,
  runLifecycleMaintenance,
  stopLifecycleSweeperForTests
};
