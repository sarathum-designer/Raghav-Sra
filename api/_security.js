/**
 * _security.js — shared security helpers for all API routes.
 * Prefixed with _ so Vercel does NOT expose it as an endpoint.
 */
const jwt      = require('jsonwebtoken');
const supabase = require('./_client');

// ── Token verification ────────────────────────────────────────────────────────
/**
 * Verifies the Bearer JWT from req.headers.authorization.
 * Returns { payload } on success or { error, status } on failure.
 */
function verifyToken(req, requiredRole) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return { error: 'No token provided.', status: 401 };
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (requiredRole && payload.role !== requiredRole)
      return { error: 'Access denied.', status: 403 };
    return { payload };
  } catch {
    return { error: 'Invalid or expired token.', status: 401 };
  }
}

// ── Rate limiting (stored in Supabase) ───────────────────────────────────────
const RATE_LIMIT_MAX    = 5;   // max failed attempts
const RATE_LIMIT_WINDOW = 15;  // minutes

/** Returns true if this identifier is currently locked out. */
async function isRateLimited(identifier) {
  const windowStart = new Date(Date.now() - RATE_LIMIT_WINDOW * 60 * 1000).toISOString();
  const { count } = await supabase
    .from('login_attempts')
    .select('*', { count: 'exact', head: true })
    .eq('identifier', identifier.toLowerCase().trim())
    .eq('success', false)
    .gte('created_at', windowStart);
  return (count || 0) >= RATE_LIMIT_MAX;
}

/** Records a login attempt. */
async function recordAttempt(identifier, ip, success) {
  await supabase.from('login_attempts').insert({
    identifier: identifier.toLowerCase().trim(),
    ip_address: ip || 'unknown',
    success:    !!success
  });
}

/** Clears failed attempts after a successful login. */
async function clearAttempts(identifier) {
  await supabase.from('login_attempts')
    .delete()
    .eq('identifier', identifier.toLowerCase().trim())
    .eq('success', false);
}

// ── Audit logging ─────────────────────────────────────────────────────────────
/**
 * Writes an audit event. Fire-and-forget (no await needed at call site).
 * event    : e.g. 'owner_login', 'doc_uploaded', 'owner_approved', 'owner_rejected'
 * actorId  : UUID of the owner or admin
 * actorType: 'owner' | 'admin'
 * targetId : UUID of the affected resource (owner or document)
 * details  : plain object with extra context
 * ip       : request IP
 */
async function writeAuditLog(event, actorId, actorType, targetId, details, ip) {
  try {
    await supabase.from('audit_log').insert({
      event,
      actor_id:   actorId   || null,
      actor_type: actorType || null,
      target_id:  targetId  || null,
      details:    details   || null,
      ip_address: ip        || 'unknown'
    });
  } catch (_) { /* never let audit failure crash a request */ }
}

// ── Magic-bytes file validation ───────────────────────────────────────────────
/**
 * Validates that the actual file bytes match the claimed MIME type.
 * Prevents file-extension spoofing (e.g. a .exe renamed to .pdf).
 */
function validateMagicBytes(buffer, mimeType) {
  if (!buffer || buffer.length < 8) return false;
  switch (mimeType) {
    case 'image/jpeg':
      // FF D8 FF
      return buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
    case 'image/png':
      // 89 50 4E 47 0D 0A 1A 0A
      return buffer[0] === 0x89 && buffer[1] === 0x50 &&
             buffer[2] === 0x4E && buffer[3] === 0x47;
    case 'application/pdf':
      // 25 50 44 46  ("%PDF")
      return buffer[0] === 0x25 && buffer[1] === 0x50 &&
             buffer[2] === 0x44 && buffer[3] === 0x46;
    default:
      return false;
  }
}

// ── Input sanitisation ────────────────────────────────────────────────────────
/**
 * Strips null bytes, control characters, trims whitespace.
 * Returns the sanitised string or '' if input isn't a string.
 */
function sanitize(value, maxLength = 255) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\0/g, '')            // null bytes
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars
    .trim()
    .slice(0, maxLength);
}

// ── IP extraction ─────────────────────────────────────────────────────────────
/** Extracts the real client IP from Vercel/proxy headers. */
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    'unknown'
  );
}

module.exports = {
  verifyToken,
  isRateLimited,
  recordAttempt,
  clearAttempts,
  writeAuditLog,
  validateMagicBytes,
  sanitize,
  getIP
};
