require('dotenv').config();
const path = require('path');
const express = require('express');
const supabase = require('./services/supabaseService');
const { startLifecycleSweeper } = require('./services/lifecycleSweeperService');
const { validateManagementSessionConfig } = require('./services/managementSessionService');
const demoRoutes = require('./routes/demoRoutes');
const manageRoutes = require('./routes/manageRoutes');
const secretRoutes = require('./routes/secretRoutes');
const viewRoutes = require('./routes/viewRoutes');
const {
  helmetMiddleware,
  generalApiLimiter,
  malformedJsonHandler,
  globalErrorHandler
} = require('./middleware/securityMiddleware');

// Validate management session configuration on startup
try {
  validateManagementSessionConfig();
} catch (err) {
  console.error(err.message);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Start background lifecycle sweeper
startLifecycleSweeper();

// Security headers
app.use(helmetMiddleware);

// Middleware
app.use(express.json({ limit: "20kb" }));
app.use(malformedJsonHandler);
app.use(express.urlencoded({ extended: true }));

// Serve static assets from public directory
app.use(express.static(path.join(__dirname, '../public')));

// General API rate limiter
app.use('/api', generalApiLimiter);

// Mount routes
app.use('/', manageRoutes);
app.use('/', viewRoutes);
app.use('/api', secretRoutes);
app.use('/api/demo', demoRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    app: 'VaultLink Secure Handover Room'
  });
});

// Database status check endpoint
app.get('/api/database-status', async (req, res) => {
  if (!supabase) {
    return res.status(500).json({
      status: 'error',
      message: 'Database connection failed'
    });
  }

  try {
    const { status, error } = await supabase.from('test_table').select('*').limit(1);

    // If status indicates unauthorized or network failure without response, fail
    if (status === 401 || status === 403 || (!status && error)) {
      return res.status(500).json({
        status: 'error',
        message: 'Database connection failed'
      });
    }

    return res.status(200).json({
      status: 'connected',
      database: 'supabase'
    });
  } catch (err) {
    return res.status(500).json({
      status: 'error',
      message: 'Database connection failed'
    });
  }
});

// Global error handler
app.use(globalErrorHandler);

// Start server if executed directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`VaultLink server is running on http://localhost:${PORT}`);
  });
}

module.exports = app;