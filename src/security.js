'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// TODO(security): Integrate OAuth 2.0 / OpenID Connect providers for federated authentication.
// TODO(security): Implement Multi-Factor Authentication (MFA / TOTP) for enhanced account security.
// TODO(security): Integrate leaked password detection (e.g., HaveIBeenPwned k-anonymity API).

/**
 * Multi-tiered secret resolution without hardcoded fallbacks.
 */
function resolveSecret() {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.trim().length >= 32) {
    return process.env.SESSION_SECRET.trim();
  }
  const secretFilePath = path.resolve(__dirname, '..', 'data', '.session_secret');
  if (fs.existsSync(secretFilePath)) {
    const fileSecret = fs.readFileSync(secretFilePath, 'utf-8').trim();
    if (fileSecret.length >= 32) {
      return fileSecret;
    }
  }
  console.warn('WARNING: Generating ephemeral session secret. Sessions are instance-isolated!');
  return crypto.randomBytes(32).toString('hex');
}

const SESSION_SECRET = resolveSecret();

/**
 * Validate password strength according to security policy:
 * - Minimum 8 characters (12+ recommended)
 * - Maximum 128 characters
 * - Allows all characters including special characters
 */
function validatePasswordStrength(password) {
  if (typeof password !== 'string') {
    return { valid: false, message: 'Password must be a valid string.' };
  }
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long.' };
  }
  if (password.length > 128) {
    return { valid: false, message: 'Password must not exceed 128 characters.' };
  }
  return { valid: true };
}

/**
 * Hash password using memory-hard crypto.scrypt with unique per-user random salt.
 */
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt}:${derivedKey.toString('hex')}`);
    });
  });
}

/**
 * Verify password against stored salt:hash using timingSafeEqual.
 */
function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    if (typeof storedHash !== 'string' || !storedHash.includes(':')) {
      return resolve(false);
    }
    const [salt, keyHex] = storedHash.split(':');
    if (!salt || !keyHex) {
      return resolve(false);
    }
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      const keyBuffer = Buffer.from(keyHex, 'hex');
      if (keyBuffer.length !== derivedKey.length) {
        return resolve(false);
      }
      resolve(crypto.timingSafeEqual(keyBuffer, derivedKey));
    });
  });
}

/**
 * Generate a cryptographically random token.
 */
function generateToken(byteLength = 32) {
  return crypto.randomBytes(byteLength).toString('hex');
}

/**
 * Sign a session ID with HMAC-SHA256.
 */
function signSessionId(sessionId) {
  const mac = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  return `${sessionId}.${mac}`;
}

/**
 * Verify and extract a signed session ID.
 */
function unsignSessionId(signedValue) {
  if (typeof signedValue !== 'string' || !signedValue.includes('.')) {
    return null;
  }
  const lastDot = signedValue.lastIndexOf('.');
  const sessionId = signedValue.slice(0, lastDot);
  const providedMac = signedValue.slice(lastDot + 1);
  if (!sessionId || !providedMac) {
    return null;
  }
  const expectedMac = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  const providedBuf = Buffer.from(providedMac, 'hex');
  const expectedBuf = Buffer.from(expectedMac, 'hex');
  if (providedBuf.length !== expectedBuf.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(providedBuf, expectedBuf)) {
    return null;
  }
  return sessionId;
}

/**
 * Mask sensitive strings (such as email or account identifiers) for safe display.
 */
function maskEmail(email) {
  if (typeof email !== 'string' || !email.includes('@')) {
    return '***';
  }
  const [local, domain] = email.split('@');
  const visibleLocal = local.length <= 2 ? local[0] + '*' : local.slice(0, 2) + '***';
  return `${visibleLocal}@${domain}`;
}

/**
 * Parse Cookie header into a safe null-prototype object.
 */
function parseCookies(cookieHeader) {
  const cookies = Object.create(null);
  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return cookies;
  }
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) {
      try {
        cookies[key] = decodeURIComponent(val);
      } catch {
        cookies[key] = val;
      }
    }
  }
  return cookies;
}

/**
 * Format Set-Cookie header with hardened security attributes.
 * Note: __Host- prefix requires Secure flag; browsers allow Secure on 127.0.0.1/localhost.
 */
function serializeSessionCookie(name, value, maxAgeSeconds, isHttps = true) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(maxAgeSeconds)}`,
  ];
  if (isHttps) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

/**
 * In-memory per-IP rate limiter to protect API endpoints against brute-force and DoS.
 */
class RateLimiter {
  constructor(windowMs = 60_000, maxRequests = 120) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.hits = new Map();
  }

  check(ip, customLimit = null) {
    const now = Date.now();
    const limit = customLimit || this.maxRequests;
    let entry = this.hits.get(ip);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + this.windowMs };
      this.hits.set(ip, entry);
    }
    entry.count += 1;
    if (this.hits.size > 5000) {
      for (const [k, v] of this.hits.entries()) {
        if (now > v.resetAt) this.hits.delete(k);
      }
    }
    return {
      allowed: entry.count <= limit,
      remaining: Math.max(0, limit - entry.count),
      resetAt: entry.resetAt,
    };
  }
}

module.exports = {
  validatePasswordStrength,
  hashPassword,
  verifyPassword,
  generateToken,
  signSessionId,
  unsignSessionId,
  maskEmail,
  parseCookies,
  serializeSessionCookie,
  RateLimiter,
};
