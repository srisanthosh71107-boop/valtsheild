const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

/**
 * Helmet Security Headers Configuration
 * Enforces Content Security Policy, Frameguard, and Content-Type sniffing prevention.
 */
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
});

/**
 * Sensitive Route Headers Middleware
 * Applied to all handover viewing, management, verification, reveal, and burn endpoints.
 */
function sensitiveHeadersMiddleware(req, res, next) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
}

/**
 * Environment check for rate-limiter bypass during automated test runs.
 * Explicit rate-limit tests can opt-in via 'x-test-rate-limit' header.
 */
const shouldSkipRateLimit = (req) => {
  const inTest = (
    process.env.NODE_ENV === 'test' ||
    process.env.npm_lifecycle_event === 'test' ||
    process.argv.some((arg) => arg.includes('test'))
  );
  return inTest && !req.headers['x-test-rate-limit'];
};

/**
 * General API routes rate limiter: 100 requests per IP per 15 minutes
 */
const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { error: 'Too many requests. Please try again later.' },
  skip: shouldSkipRateLimit
});

/**
 * Create secret endpoint rate limiter: 10 requests per IP per hour
 */
const createSecretLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { error: 'Too many secret creation requests. Please try again later.' },
  skip: shouldSkipRateLimit
});

/**
 * Reveal endpoint rate limiter: 10 requests per IP per 10 minutes
 */
const revealLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { error: 'Too many reveal attempts. Please try again later.' },
  skip: shouldSkipRateLimit
});

/**
 * Panic Burn endpoint rate limiter: 10 requests per IP per 15 minutes
 */
const panicBurnLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { error: 'Too many panic burn requests. Please try again later.' },
  skip: shouldSkipRateLimit
});

/**
 * Malformed JSON body parser error handler
 */
function malformedJsonHandler(err, req, res, next) {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed request payload.' });
  }
  next(err);
}

/**
 * Global Error Handler
 * Strictly prevents stack trace leaks or raw database/crypto errors in API responses.
 */
function globalErrorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500;
  return res.status(status).json({
    error: 'An unexpected error occurred. Please try again.'
  });
}

module.exports = {
  helmetMiddleware,
  sensitiveHeadersMiddleware,
  generalApiLimiter,
  createSecretLimiter,
  revealLimiter,
  panicBurnLimiter,
  malformedJsonHandler,
  globalErrorHandler
};
