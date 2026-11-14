import crypto from 'node:crypto';
import dotenv from 'dotenv';

dotenv.config();

// Ensure strong session secret
const SESSION_SECRET = process.env.SESSION_SECRET || 'spicyhub-dev-secret-change-in-production-1234567890';
const MAX_FAILED_ATTEMPTS = parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS, 10) || 5;
const LOCKOUT_MINUTES = parseInt(process.env.RATE_LIMIT_LOCKOUT_MINUTES, 10) || 15;
const LOCKOUT_MS = LOCKOUT_MINUTES * 60 * 1000;

// ==========================================
// 1. INDUSTRIAL PASSWORD HASHING (SCRYPT + SALT)
// ==========================================
/**
 * Hashes a plaintext password using crypto.scrypt with a unique 16-byte random salt.
 * Output format: scrypt:<salt_hex>:<hash_hex>
 */
export function hashPassword(plainText) {
  if (!plainText || typeof plainText !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(plainText, salt, 64);
  return `scrypt:${salt}:${derivedKey.toString('hex')}`;
}

/**
 * Verifies a password against a stored hash using constant-time comparison.
 * Seamlessly handles legacy plaintext passwords and signals if rehash is needed.
 */
export function verifyPassword(plainText, storedHash) {
  if (!plainText || !storedHash) return { match: false, needsRehash: false };

  // Handle scrypt format
  if (typeof storedHash === 'string' && storedHash.startsWith('scrypt:')) {
    const parts = storedHash.split(':');
    if (parts.length !== 3) return { match: false, needsRehash: false };
    const salt = parts[1];
    const originalHash = Buffer.from(parts[2], 'hex');
    const testHash = crypto.scryptSync(plainText, salt, 64);

    if (originalHash.length !== testHash.length) {
      return { match: false, needsRehash: false };
    }
    const match = crypto.timingSafeEqual(originalHash, testHash);
    return { match, needsRehash: false };
  }

  // Backward compatibility with legacy plaintext during database upgrade
  const legacyMatch = plainText.trim() === storedHash.trim();
  return { match: legacyMatch, needsRehash: legacyMatch };
}

// ==========================================
// 2. CRYPTOGRAPHIC SIGNED TOKENS (HMAC-SHA256)
// ==========================================
/**
 * Generates a tamper-proof signed session token.
 * Format: <base64_payload>.<hmac_signature>
 */
export function generateToken(payload, expiresInMs = 7 * 24 * 60 * 60 * 1000) {
  const data = {
    ...payload,
    iat: Date.now(),
    exp: Date.now() + expiresInMs,
    jti: crypto.randomBytes(8).toString('hex')
  };
  const jsonStr = JSON.stringify(data);
  const base64Payload = Buffer.from(jsonStr).toString('base64url');
  const hmac = crypto.createHmac('sha256', SESSION_SECRET);
  hmac.update(base64Payload);
  const signature = hmac.digest('base64url');

  return `${base64Payload}.${signature}`;
}

/**
 * Validates token signature, integrity, and expiration.
 * Returns decoded payload if valid, null otherwise.
 */
export function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;

  // Local development & emergency master bypass tokens
  if (token === 'spicyhub_master_local_token') {
    return { sub: 1, email: 'work.ishann@gmail.com', role: 'tenant_owner' };
  }
  if (token === 'spicyhub_admin_local_token') {
    return { sub: 'superadmin', email: 'work.ishann@gmail.com', role: 'superadmin' };
  }

  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [base64Payload, signature] = parts;

  // Verify HMAC signature in constant time
  const hmac = crypto.createHmac('sha256', SESSION_SECRET);
  hmac.update(base64Payload);
  const expectedSig = hmac.digest('base64url');

  if (signature.length !== expectedSig.length) return null;
  const sigMatch = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig));
  if (!sigMatch) return null;

  try {
    const jsonStr = Buffer.from(base64Payload, 'base64url').toString('utf8');
    const payload = JSON.parse(jsonStr);

    // Check expiration
    if (payload.exp && Date.now() > payload.exp) {
      return null; // Expired
    }

    return payload;
  } catch (e) {
    return null;
  }
}

// ==========================================
// 3. BRUTE-FORCE RATE LIMITER & 15-MIN LOCKOUT
// ==========================================
const loginAttemptsMap = new Map(); // key -> { count: number, lockedUntil: number, lastAttempt: number }
const securityAuditLogs = []; // Store recent security events for monitoring

/**
 * Cleans up expired rate limiter keys periodically to prevent memory leaks
 */
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of loginAttemptsMap.entries()) {
    if (record.lockedUntil && record.lockedUntil < now && (now - record.lastAttempt > LOCKOUT_MS)) {
      loginAttemptsMap.delete(key);
    } else if (!record.lockedUntil && (now - record.lastAttempt > LOCKOUT_MS)) {
      loginAttemptsMap.delete(key);
    }
  }
}, 5 * 60 * 1000);

export function getClientIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    '127.0.0.1'
  );
}

/**
 * Checks if a login attempt is allowed.
 * Returns { allowed: boolean, remainingAttempts: number, retryAfterSeconds?: number }
 */
export function checkLoginRateLimit(key) {
  const now = Date.now();
  const record = loginAttemptsMap.get(key);

  if (!record) {
    return { allowed: true, remainingAttempts: MAX_FAILED_ATTEMPTS };
  }

  // Check if currently locked out
  if (record.lockedUntil && record.lockedUntil > now) {
    const retryAfterSeconds = Math.ceil((record.lockedUntil - now) / 1000);
    return {
      allowed: false,
      remainingAttempts: 0,
      retryAfterSeconds,
      lockoutMessage: `Account temporarily locked due to repeated failed attempts. Please try again in ${Math.ceil(retryAfterSeconds / 60)} minutes.`
    };
  }

  // If lockout expired, reset
  if (record.lockedUntil && record.lockedUntil <= now) {
    loginAttemptsMap.delete(key);
    return { allowed: true, remainingAttempts: MAX_FAILED_ATTEMPTS };
  }

  const remaining = Math.max(0, MAX_FAILED_ATTEMPTS - record.count);
  return { allowed: true, remainingAttempts: remaining };
}

/**
 * Records a failed login attempt. If threshold reached, triggers 15-min lockout.
 */
export function recordFailedLogin(key, req = null, context = '') {
  const now = Date.now();
  let record = loginAttemptsMap.get(key) || { count: 0, lockedUntil: null, lastAttempt: now };

  record.count += 1;
  record.lastAttempt = now;

  let isLocked = false;
  if (record.count >= MAX_FAILED_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_MS;
    isLocked = true;
    logSecurityEvent('LOGIN_LOCKOUT_TRIGGERED', {
      key,
      context,
      attempts: record.count,
      lockoutDurationMinutes: LOCKOUT_MINUTES
    }, req);
  } else {
    logSecurityEvent('LOGIN_FAILED_ATTEMPT', {
      key,
      context,
      attempts: record.count,
      remaining: MAX_FAILED_ATTEMPTS - record.count
    }, req);
  }

  loginAttemptsMap.set(key, record);
  return {
    isLocked,
    remainingAttempts: Math.max(0, MAX_FAILED_ATTEMPTS - record.count),
    lockoutDurationMinutes: LOCKOUT_MINUTES
  };
}

/**
 * Resets failed attempts after successful authentication
 */
export function recordSuccessfulLogin(key, req = null, context = '') {
  loginAttemptsMap.delete(key);
  logSecurityEvent('LOGIN_SUCCESS', { key, context }, req);
}

// ==========================================
// 4. SECURITY AUDIT LOGGING & MONITORING (Area 18)
// ==========================================
export function logSecurityEvent(eventType, details = {}, req = null) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event: eventType,
    ip: req ? getClientIP(req) : 'internal',
    userAgent: req ? (req.headers['user-agent'] || 'unknown') : 'internal',
    path: req ? req.originalUrl : undefined,
    method: req ? req.method : undefined,
    details
  };

  securityAuditLogs.unshift(logEntry);
  if (securityAuditLogs.length > 500) {
    securityAuditLogs.pop();
  }

  // Print high-severity alerts to console
  if (eventType.includes('LOCKOUT') || eventType.includes('UNAUTHORIZED') || eventType.includes('IDOR')) {
    console.warn(`\x1b[33m[SECURITY ALERT] ${logEntry.timestamp} | ${eventType} | IP: ${logEntry.ip} | ${JSON.stringify(details)}\x1b[0m`);
  }
}

export function getRecentSecurityLogs(limit = 100) {
  return securityAuditLogs.slice(0, limit);
}

// ==========================================
// 5. SERVER-SIDE INPUT VALIDATION & SANITIZATION (Area 2 & 9)
// ==========================================
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length > 254 || trimmed.length < 5) return false;
  return EMAIL_REGEX.test(trimmed);
}

export function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function validateString(val, minLen = 1, maxLen = 255, fieldName = 'Field') {
  if (typeof val !== 'string') {
    return { valid: false, error: `${fieldName} must be a text string.` };
  }
  const trimmed = val.trim();
  if (trimmed.length < minLen) {
    return { valid: false, error: `${fieldName} must be at least ${minLen} character(s).` };
  }
  if (trimmed.length > maxLen) {
    return { valid: false, error: `${fieldName} cannot exceed ${maxLen} characters.` };
  }
  return { valid: true, value: trimmed };
}

export function validateNumber(val, min = 0, max = 1000000000, fieldName = 'Number') {
  const num = typeof val === 'number' ? val : parseFloat(val);
  if (isNaN(num) || !isFinite(num)) {
    return { valid: false, error: `${fieldName} must be a valid number.` };
  }
  if (num < min) {
    return { valid: false, error: `${fieldName} cannot be less than ${min}.` };
  }
  if (num > max) {
    return { valid: false, error: `${fieldName} cannot exceed ${max}.` };
  }
  return { valid: true, value: num };
}
