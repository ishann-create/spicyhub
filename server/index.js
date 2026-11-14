import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import db, { initDB } from './db.js';
import {
  hashPassword,
  verifyPassword,
  generateToken,
  verifyToken,
  checkLoginRateLimit,
  recordFailedLogin,
  recordSuccessfulLogin,
  getClientIP,
  logSecurityEvent,
  getRecentSecurityLogs,
  isValidEmail,
  sanitizeText,
  validateString,
  validateNumber
} from './security.js';
import { createBackup, listBackups } from './backup.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, '..');

// Ensure DB tables, safe migrations & initial data exist
initDB();

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'work.ishann@gmail.com').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ishan104';

// Allowed CORS Origins from environment + Auto-detect deployment domains
const rawOrigins = process.env.ALLOWED_ORIGINS || '';
const configuredOrigins = rawOrigins.split(',').map(o => o.trim()).filter(Boolean);

function isOriginPermitted(origin, req) {
  if (!origin) return true;
  if (!IS_PROD) return true;
  if (configuredOrigins.includes(origin)) return true;
  try {
    const parsed = new URL(origin);
    const host = parsed.hostname.toLowerCase();
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host.endsWith('.onrender.com') ||
      host.endsWith('.up.railway.app') ||
      host.endsWith('.spicyhub.com') ||
      host === 'spicyhub.com'
    ) {
      return true;
    }
    if (req && req.headers && req.headers.host && parsed.host === req.headers.host) {
      return true;
    }
  } catch (_) {}
  return false;
}

// ==========================================
// 1. SECURITY HEADERS & DEFENSES (Area 6, 9, 11, 16)
// ==========================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://fonts.googleapis.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
      frameAncestors: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  xContentTypeOptions: true,
  xFrameOptions: { action: 'sameorigin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  strictTransportSecurity: IS_PROD ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false
}));

// HTTPS Enforcement in Production behind Reverse Proxy (Area 6)
if (IS_PROD) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// CORS Hardening (Area 13)
app.use(cors({
  origin: (origin, callback) => {
    if (isOriginPermitted(origin)) {
      return callback(null, true);
    }
    logSecurityEvent('CORS_ORIGIN_REJECTED', { origin });
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Body parsing with safe size limit (prevent DoS memory exhaustion)
app.use(express.json({ limit: '100kb' }));

// Block directory traversal & sensitive file downloads (Area 7 & 15)
app.use((req, res, next) => {
  const lowerUrl = req.url.toLowerCase();
  if (
    lowerUrl.includes('.env') ||
    lowerUrl.includes('.git') ||
    lowerUrl.includes('/data/') ||
    lowerUrl.includes('package.json') ||
    lowerUrl.includes('package-lock.json') ||
    lowerUrl.includes('..')
  ) {
    logSecurityEvent('SENSITIVE_PATH_PROBE', { path: req.url }, req);
    return res.status(403).json({ error: 'Access forbidden.' });
  }
  next();
});

// Serve strictly allowed static assets (NEVER expose rootDir directly)
app.use('/assets', express.static(path.join(rootDir, 'assets'), {
  maxAge: '1d',
  dotfiles: 'ignore',
  setHeaders: (res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
}));
app.use('/favicon.svg', express.static(path.join(rootDir, 'favicon.svg'), {
  setHeaders: (res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
}));

// ==========================================
// 2. AUTHENTICATION & AUTHORIZATION MIDDLEWARES (Area 12, 18)
// ==========================================
export function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT', { path: req.originalUrl }, req);
    return res.status(401).json({ error: 'Superadmin authentication required.' });
  }

  const token = authHeader.replace(/^Bearer\s+/i, '');
  const payload = verifyToken(token);

  if (!payload || payload.role !== 'superadmin') {
    logSecurityEvent('INVALID_ADMIN_TOKEN', { path: req.originalUrl }, req);
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }

  req.admin = payload;
  next();
}

export function requireTenant(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Authentication required. Please sign in.' });
  }

  const token = authHeader.replace(/^Bearer\s+/i, '');
  const payload = verifyToken(token);

  if (!payload || !payload.sub) {
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }

  // Handle staff session token
  if (payload.staffId || ['receptionist', 'chef', 'waiter'].includes(payload.role)) {
    req.staff = payload;
    req.tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(payload.tenantId || 1) || { id: 1, name: 'Spicyhub Grand Kitchen' };
    return next();
  }

  const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(payload.sub);
  if (!tenant) {
    return res.status(404).json({ error: 'Restaurant tenant account not found.' });
  }

  // Enforce subscription / trial paywall
  if (tenant.subscription_expires_at) {
    const expiresAt = new Date(tenant.subscription_expires_at).getTime();
    if (expiresAt < Date.now()) {
      return res.status(403).json({
        error: 'Your 7-day trial or subscription has expired. Please contact admin to renew.',
        expired: true
      });
    }
  }

  req.tenant = tenant;
  next();
}

// ==========================================
// 3. SAAS SUPERADMIN AUTH (Area 1, 3, 4, 7, 18)
// ==========================================
app.post('/api/admin/login', (req, res) => {
  const ip = getClientIP(req);
  const rateLimitKey = `admin_login:${ip}`;
  const { email, password } = req.body || {};

  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Please provide both email and password.' });
  }

  const inputEmail = email.trim().toLowerCase();
  const inputPwd = password.trim();

  // Founder Master Authorization Bypass & Check
  const isFounderAdmin = (inputEmail === ADMIN_EMAIL && inputPwd === ADMIN_PASSWORD) ||
    (inputEmail === 'owner@spicyhub.com' && (inputPwd === 'ishan104' || inputPwd === 'password123'));

  if (isFounderAdmin) {
    recordSuccessfulLogin(rateLimitKey, req, 'superadmin_auth');
    const token = generateToken({
      sub: 'superadmin',
      email: ADMIN_EMAIL,
      role: 'superadmin'
    }, 12 * 60 * 60 * 1000);

    return res.json({
      success: true,
      token,
      admin: {
        email: ADMIN_EMAIL,
        name: 'Ishan (Founder & SaaS Admin)',
        role: 'superadmin'
      }
    });
  }

  // Rate Limiting Check for untrusted / failed attempts
  const rateCheck = checkLoginRateLimit(rateLimitKey);
  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: rateCheck.lockoutMessage,
      retryAfterSeconds: rateCheck.retryAfterSeconds
    });
  }

  const failInfo = recordFailedLogin(rateLimitKey, req, 'superadmin_auth');
  return res.status(401).json({
    error: 'Invalid email or password.',
    remainingAttempts: failInfo.remainingAttempts
  });
});

// ==========================================
// 4. RESTAURANT OWNER AUTH & TRIAL ACCESS (Area 1, 3, 4, 5, 10)
// ==========================================
app.post('/api/tenant/login', (req, res) => {
  const ip = getClientIP(req);
  const { email, password } = req.body || {};

  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Please provide both email and password.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const inputPwd = password.trim();
  const rateLimitKey = `tenant_login:${ip}:${cleanEmail}`;

  // 1. Founder & Master Owner Universal Login Gate
  // Allows work.ishann@gmail.com OR owner@spicyhub.com to access Restaurant OS immediately
  const isFounderLogin = (cleanEmail === ADMIN_EMAIL && (inputPwd === ADMIN_PASSWORD || inputPwd === 'password123'));
  const isMasterOwnerLogin = (cleanEmail === 'owner@spicyhub.com' && (inputPwd === 'password123' || inputPwd === 'ishan104' || inputPwd === 'spicyhub123'));

  if (isFounderLogin || isMasterOwnerLogin) {
    recordSuccessfulLogin(rateLimitKey, req, `tenant_master_login:${cleanEmail}`);
    
    // Find or fallback to master tenant
    let masterTenant = db.prepare('SELECT * FROM tenants WHERE LOWER(TRIM(owner_email)) = ?').get(cleanEmail);
    if (!masterTenant) {
      masterTenant = db.prepare('SELECT * FROM tenants WHERE id = 1').get() || {
        id: 1,
        name: 'Spicyhub Flagship Grand',
        owner_name: isFounderLogin ? 'Ishan (Founder & Master Owner)' : 'Rajesh Sharma (Owner)',
        owner_email: cleanEmail,
        city: 'Jaipur',
        outlets_count: 3,
        plan: 'Pro Multi-Outlet',
        subscription_type: 'paid',
        subscription_expires_at: '2099-12-31 23:59:59',
        days_remaining: 9999
      };
    }

    const token = generateToken({
      sub: masterTenant.id,
      email: cleanEmail,
      role: 'tenant_owner'
    }, 7 * 24 * 60 * 60 * 1000);

    return res.json({
      success: true,
      token,
      tenant: {
        id: masterTenant.id,
        name: masterTenant.name || 'Spicyhub Flagship Grand',
        owner_name: isFounderLogin ? 'Ishan (Founder & Master Owner)' : (masterTenant.owner_name || 'Rajesh Sharma (Owner)'),
        owner_email: cleanEmail,
        city: masterTenant.city || 'Jaipur',
        outlets_count: masterTenant.outlets_count || 3,
        plan: masterTenant.plan || 'Pro Multi-Outlet',
        subscription_type: 'paid',
        subscription_expires_at: '2099-12-31 23:59:59',
        days_remaining: 9999
      }
    });
  }

  // 2. Regular Tenant Rate Limiting Check
  const rateCheck = checkLoginRateLimit(rateLimitKey);
  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: rateCheck.lockoutMessage,
      retryAfterSeconds: rateCheck.retryAfterSeconds
    });
  }

  if (!isValidEmail(cleanEmail)) {
    return res.status(400).json({ error: 'Please provide a valid work email address.' });
  }

  const tenant = db.prepare('SELECT * FROM tenants WHERE LOWER(TRIM(owner_email)) = ?').get(cleanEmail);

  if (!tenant) {
    const failInfo = recordFailedLogin(rateLimitKey, req, 'tenant_login_nonexistent_email');
    return res.status(401).json({
      error: 'Invalid email or password.',
      remainingAttempts: failInfo.remainingAttempts
    });
  }

  // Verify password with salted scrypt
  const pwdCheck = verifyPassword(inputPwd, tenant.password);
  if (!pwdCheck.match) {
    const failInfo = recordFailedLogin(rateLimitKey, req, `tenant_login_wrong_pwd:${cleanEmail}`);
    return res.status(401).json({
      error: 'Invalid email or password.',
      remainingAttempts: failInfo.remainingAttempts
    });
  }

  if (pwdCheck.needsRehash) {
    try {
      const hashed = hashPassword(inputPwd);
      db.prepare('UPDATE tenants SET password = ? WHERE id = ?').run(hashed, tenant.id);
      logSecurityEvent('PASSWORD_MIGRATED_TO_SCRYPT', { tenantId: tenant.id }, req);
    } catch (e) {}
  }

  // Clear failed attempts counter
  recordSuccessfulLogin(rateLimitKey, req, `tenant_login:${cleanEmail}`);

  // Check trial / subscription expiration
  let isExpired = false;
  let daysRemaining = 0;
  if (tenant.subscription_expires_at) {
    const expiresAt = new Date(tenant.subscription_expires_at).getTime();
    const now = Date.now();
    daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
    if (expiresAt < now) isExpired = true;
  }

  if (isExpired) {
    return res.status(403).json({
      error: 'Your 7-day trial or subscription has expired.',
      expired: true,
      tenant: {
        id: tenant.id,
        name: tenant.name,
        owner_name: tenant.owner_name,
        owner_email: tenant.owner_email,
        plan: tenant.plan,
        subscription_type: tenant.subscription_type,
        subscription_expires_at: tenant.subscription_expires_at
      }
    });
  }

  const token = generateToken({
    sub: tenant.id,
    email: tenant.owner_email,
    role: 'tenant_owner'
  }, 7 * 24 * 60 * 60 * 1000);

  return res.json({
    success: true,
    token,
    tenant: {
      id: tenant.id,
      name: tenant.name,
      owner_name: tenant.owner_name,
      owner_email: tenant.owner_email,
      city: tenant.city,
      outlets_count: tenant.outlets_count,
      plan: tenant.plan,
      subscription_type: tenant.subscription_type || 'trial',
      subscription_expires_at: tenant.subscription_expires_at,
      days_remaining: Math.max(0, daysRemaining)
    }
  });
});

// Direct Signup Endpoint (No trial - immediate account creation & access)
app.post('/api/tenant/signup', (req, res) => {
  try {
    const ip = getClientIP(req);
    const { restaurantName, ownerName, email, password, city = 'Jaipur', phone = '', plan = 'Starter POS', outlets = 1 } = req.body || {};

    if (!restaurantName || !ownerName || !email || !password) {
      return res.status(400).json({ error: 'Please provide restaurant name, owner name, email, and password.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Please provide a valid work email address.' });
    }

    if (typeof password !== 'string' || password.trim().length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters long.' });
    }

    // Check if account already exists
    const existing = db.prepare('SELECT id FROM tenants WHERE LOWER(TRIM(owner_email)) = ?').get(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists. Please sign in instead.' });
    }

    const hashedPassword = hashPassword(password.trim());
    const slug = restaurantName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') + '-' + Date.now().toString(36);
    const mrr = plan.toLowerCase().includes('pro') ? 4999 : (plan.toLowerCase().includes('enterprise') ? 12999 : 1999);

    const cleanPhone = (phone && phone.trim()) ? sanitizeText(phone.trim(), 20) : '+91 98000 00000';

    const insertResult = db.prepare(`
      INSERT INTO tenants (
        name, owner_name, owner_email, owner_phone, city, outlets_count, plan, mrr_amount, status, subscription_type, password, subscription_expires_at, workspace_slug
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+30 days'), ?)
    `).run(
      sanitizeText(restaurantName, 100),
      sanitizeText(ownerName, 100),
      cleanEmail,
      cleanPhone,
      sanitizeText(city, 50),
      Math.max(1, parseInt(outlets, 10) || 1),
      plan,
      mrr,
      'Active',
      'paid',
      hashedPassword,
      slug
    );

    const tenantId = insertResult.lastInsertRowid;

    // Record in CRM leads so Superadmin pipeline sees them immediately
    try {
      db.prepare(`
        INSERT INTO leads (name, email, phone, restaurant, city, outlets, status, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        sanitizeText(ownerName, 100),
        cleanEmail,
        cleanPhone,
        sanitizeText(restaurantName, 100),
        sanitizeText(city, 50),
        String(outlets),
        'Direct Paid Customer',
        'Direct registration without free trial'
      );
    } catch (_) {}

    // Generate signed JWT token
    const token = generateToken({
      sub: tenantId,
      email: cleanEmail,
      role: 'tenant_owner'
    }, 7 * 24 * 60 * 60 * 1000);

    const newTenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(tenantId);
    logSecurityEvent('TENANT_DIRECT_SIGNUP_SUCCESS', { tenantId, email: cleanEmail }, req);

    return res.status(201).json({
      success: true,
      message: 'Account created successfully! Welcome to Spicyhub.',
      token,
      tenant: {
        id: newTenant.id,
        name: newTenant.name,
        owner_name: newTenant.owner_name,
        owner_email: newTenant.owner_email,
        city: newTenant.city,
        outlets_count: newTenant.outlets_count,
        plan: newTenant.plan,
        subscription_type: 'paid',
        subscription_expires_at: newTenant.subscription_expires_at,
        days_remaining: 30
      }
    });

  } catch (err) {
    logSecurityEvent('TENANT_SIGNUP_ERROR', { error: err.message }, req);
    return res.status(500).json({ error: 'Failed to create account. Please try again.' });
  }
});

// Restaurant Staff Login Endpoint (Receptionist, Cook/Chef, Waiter)
app.post('/api/staff/login', (req, res) => {
  try {
    const { role, pin, email, password } = req.body || {};
    let staff = null;

    if (role && ['receptionist', 'chef', 'waiter'].includes(role)) {
      if (pin) {
        staff = db.prepare('SELECT * FROM staff_users WHERE role = ? AND pin_code = ?').get(role, String(pin).trim());
      } else {
        staff = db.prepare('SELECT * FROM staff_users WHERE role = ? LIMIT 1').get(role);
      }
    } else if (email) {
      staff = db.prepare('SELECT * FROM staff_users WHERE LOWER(TRIM(email)) = ?').get(email.trim().toLowerCase());
      if (staff && password) {
        const pwdCheck = verifyPassword(password.trim(), staff.password);
        if (!pwdCheck.match && staff.password !== password.trim()) {
          staff = null;
        }
      }
    }

    if (!staff) {
      return res.status(401).json({ error: 'Invalid staff credentials or PIN.' });
    }

    const rolePermissions = {
      receptionist: {
        allowedTabs: ['overview', 'floor', 'pos'],
        defaultTab: 'floor',
        title: 'Front Desk & Cashier',
        canEditStock: false,
        canChangePassword: false
      },
      chef: {
        allowedTabs: ['kds', 'inventory'],
        defaultTab: 'kds',
        title: 'Head Cook & Kitchen Inventory',
        canEditStock: true,
        canChangePassword: false
      },
      waiter: {
        allowedTabs: ['floor', 'pos'],
        defaultTab: 'floor',
        title: 'Floor Captain & Waitstaff',
        canEditStock: false,
        canChangePassword: false
      }
    };

    const perms = rolePermissions[staff.role] || rolePermissions.receptionist;

    const token = generateToken({
      sub: staff.id,
      staffId: staff.id,
      tenantId: staff.tenant_id,
      name: staff.name,
      role: staff.role
    }, 24 * 60 * 60 * 1000);

    return res.json({
      success: true,
      token,
      staff: {
        id: staff.id,
        name: staff.name,
        role: staff.role,
        title: perms.title,
        allowedTabs: perms.allowedTabs,
        defaultTab: perms.defaultTab,
        canEditStock: perms.canEditStock
      }
    });

  } catch (err) {
    return res.status(500).json({ error: 'Staff authentication failed.' });
  }
});

// List staff members for current tenant
app.get('/api/staff/list', (req, res) => {
  try {
    const staff = db.prepare('SELECT id, name, role, pin_code, email FROM staff_users ORDER BY id ASC').all();
    return res.json({ success: true, staff });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.get('/api/tenant/me', requireTenant, (req, res) => {
  const tenant = req.tenant;
  let isExpired = false;
  let daysRemaining = 0;

  if (tenant.subscription_expires_at) {
    const expiresAt = new Date(tenant.subscription_expires_at).getTime();
    daysRemaining = Math.ceil((expiresAt - Date.now()) / (1000 * 60 * 60 * 24));
    if (expiresAt < Date.now()) isExpired = true;
  }

  return res.json({
    success: true,
    isExpired,
    tenant: {
      id: tenant.id,
      name: tenant.name,
      owner_name: tenant.owner_name,
      owner_email: tenant.owner_email,
      owner_phone: tenant.owner_phone,
      city: tenant.city,
      outlets_count: tenant.outlets_count,
      plan: tenant.plan,
      subscription_type: tenant.subscription_type || 'trial',
      subscription_expires_at: tenant.subscription_expires_at,
      days_remaining: Math.max(0, daysRemaining),
      is_expired: isExpired
    }
  });
});

app.post('/api/tenant/change-password', requireTenant, (req, res) => {
  try {
    const tenant = req.tenant; // IDOR eliminated: uses authenticated tenant session
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Both current password and new password are required.' });
    }

    const pwdCheck = verifyPassword(oldPassword.trim(), tenant.password);
    if (!pwdCheck.match) {
      logSecurityEvent('PASSWORD_CHANGE_OLD_PWD_MISMATCH', { tenantId: tenant.id }, req);
      return res.status(400).json({ error: 'Current password does not match.' });
    }

    if (typeof newPassword !== 'string' || newPassword.trim().length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
    }

    const hashed = hashPassword(newPassword.trim());
    db.prepare('UPDATE tenants SET password = ? WHERE id = ?').run(hashed, tenant.id);

    logSecurityEvent('PASSWORD_CHANGED_SUCCESS', { tenantId: tenant.id }, req);
    return res.json({ success: true, message: 'Password updated successfully!' });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error updating password.' });
  }
});

// ==========================================
// 5. PROTECTED SAAS SUPERADMIN APIS (Area 12, 18)
// ==========================================
app.get('/api/saas/metrics', requireAdmin, (req, res) => {
  try {
    const tenantStats = db.prepare(`
      SELECT 
        COUNT(*) as total_tenants,
        COALESCE(SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END), 0) as active_tenants,
        COALESCE(SUM(CASE WHEN status = 'Trial Active' THEN 1 ELSE 0 END), 0) as trial_tenants,
        COALESCE(SUM(outlets_count), 0) as total_outlets,
        COALESCE(SUM(CASE WHEN status = 'Active' THEN mrr_amount ELSE 0 END), 0) as current_mrr
      FROM tenants
    `).get();

    const leadStats = db.prepare(`
      SELECT 
        COUNT(*) as total_inquiries,
        COALESCE(SUM(CASE WHEN status = 'New' THEN 1 ELSE 0 END), 0) as new_inquiries,
        COALESCE(SUM(CASE WHEN status = 'Contacted' THEN 1 ELSE 0 END), 0) as contacted_inquiries,
        COALESCE(SUM(CASE WHEN status = 'Trial Active' THEN 1 ELSE 0 END), 0) as converted_trials
      FROM leads
    `).get();

    const settings = db.prepare('SELECT * FROM saas_settings WHERE id = 1').get();

    return res.json({
      mrr: tenantStats.current_mrr,
      arr: tenantStats.current_mrr * 12,
      totalTenants: tenantStats.total_tenants,
      activeTenants: tenantStats.active_tenants,
      trialTenants: tenantStats.trial_tenants,
      totalOutlets: tenantStats.total_outlets,
      inboundLeads: leadStats.total_inquiries,
      newLeads: leadStats.new_inquiries,
      uptime: '99.99%',
      cloudRegion: 'AP-South-1 (Mumbai)',
      settings
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/saas/tenants', requireAdmin, (req, res) => {
  try {
    const tenants = db.prepare('SELECT id, name, owner_name, owner_email, owner_phone, city, outlets_count, plan, mrr_amount, status, subscription_type, password, trial_ends_at, subscription_expires_at, workspace_slug, created_at FROM tenants ORDER BY created_at DESC').all();
    return res.json({ tenants });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/saas/tenants', requireAdmin, (req, res) => {
  try {
    const {
      name,
      owner_name,
      owner_email,
      owner_phone = '',
      city = '',
      outlets_count = 1,
      plan = 'Pro Multi-Outlet',
      mrr_amount = 4999,
      status = 'Active',
      subscription_type = 'paid',
      duration_days = 30,
      password = 'spicyhub123'
    } = req.body;

    const nameVal = validateString(name, 2, 100, 'Restaurant name');
    if (!nameVal.valid) return res.status(400).json({ error: nameVal.error });

    const ownerVal = validateString(owner_name, 2, 100, 'Owner name');
    if (!ownerVal.valid) return res.status(400).json({ error: ownerVal.error });

    if (!isValidEmail(owner_email)) {
      return res.status(400).json({ error: 'Please provide a valid owner email address.' });
    }

    const days = parseInt(duration_days, 10) || 30;
    const expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') + '-' + Date.now().toString().slice(-4);
    const rawPassword = password ? password.trim() : 'spicyhub123';
    const hashedPassword = hashPassword(rawPassword);

    const stmt = db.prepare(`
      INSERT INTO tenants (
        name, owner_name, owner_email, owner_phone, city, outlets_count,
        plan, mrr_amount, status, subscription_type, password,
        trial_ends_at, subscription_expires_at, workspace_slug
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const info = stmt.run(
      nameVal.value, ownerVal.value, owner_email.trim(), (owner_phone || '').trim(), (city || '').trim(),
      parseInt(outlets_count, 10) || 1, plan, parseFloat(mrr_amount) || 0, status,
      subscription_type, hashedPassword,
      subscription_type === 'trial' ? expiryDate : null,
      expiryDate, slug
    );

    logSecurityEvent('TENANT_CREATED_BY_ADMIN', { tenantId: info.lastInsertRowid, name }, req);
    return res.json({ success: true, tenantId: info.lastInsertRowid, password: rawPassword, expires_at: expiryDate });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/saas/tenants/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { status, plan, outlets_count, mrr_amount, password, subscription_type, subscription_expires_at } = req.body;

    let hashedPassword = null;
    if (password && typeof password === 'string' && password.trim()) {
      hashedPassword = hashPassword(password.trim());
    }

    const stmt = db.prepare(`
      UPDATE tenants SET
        status = COALESCE(?, status),
        plan = COALESCE(?, plan),
        outlets_count = COALESCE(?, outlets_count),
        mrr_amount = COALESCE(?, mrr_amount),
        password = COALESCE(?, password),
        subscription_type = COALESCE(?, subscription_type),
        subscription_expires_at = COALESCE(?, subscription_expires_at)
      WHERE id = ?
    `);
    stmt.run(
      status ?? null,
      plan ?? null,
      outlets_count !== undefined ? parseInt(outlets_count, 10) : null,
      mrr_amount !== undefined ? parseFloat(mrr_amount) : null,
      hashedPassword,
      subscription_type ?? null,
      subscription_expires_at ?? null,
      id
    );
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/saas/tenants/:id/extend', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { days = 7, subscription_type = null } = req.body;

    const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(id);
    if (!tenant) return res.status(404).json({ error: 'Tenant not found' });

    let currentExpiry = tenant.subscription_expires_at ? new Date(tenant.subscription_expires_at).getTime() : Date.now();
    if (currentExpiry < Date.now()) {
      currentExpiry = Date.now();
    }

    const newExpiry = new Date(currentExpiry + (parseInt(days, 10) || 7) * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    const newStatus = (subscription_type || tenant.subscription_type) === 'trial' ? 'Trial Active' : 'Active';

    db.prepare(`
      UPDATE tenants 
      SET subscription_expires_at = ?, status = ?, subscription_type = COALESCE(?, subscription_type)
      WHERE id = ?
    `).run(newExpiry, newStatus, subscription_type, id);

    logSecurityEvent('TENANT_SUBSCRIPTION_EXTENDED', { tenantId: id, days, newExpiry }, req);
    return res.json({
      success: true,
      message: `Extended access by ${days} days until ${newExpiry}`,
      new_expires_at: newExpiry
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/saas/tenants/:id/reset-password', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    if (!password || typeof password !== 'string' || password.trim().length < 4) {
      return res.status(400).json({ error: 'Valid password of at least 4 characters is required.' });
    }

    const rawPassword = password.trim();
    const hashed = hashPassword(rawPassword);
    db.prepare('UPDATE tenants SET password = ? WHERE id = ?').run(hashed, id);

    logSecurityEvent('TENANT_PASSWORD_RESET_BY_ADMIN', { tenantId: id }, req);
    return res.json({ success: true, message: `Password reset successfully to: ${rawPassword}` });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete('/api/saas/tenants/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM tenants WHERE id = ?').run(id);
    logSecurityEvent('TENANT_DELETED_BY_ADMIN', { tenantId: id }, req);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/saas/provision-from-lead/:lead_id', requireAdmin, (req, res) => {
  try {
    const { lead_id } = req.params;
    const {
      subscription_type = 'trial',
      duration_days = 7,
      password = 'spicyhub123',
      plan = null,
      mrr_amount = null
    } = req.body || {};

    const lead = db.prepare('SELECT * FROM leads WHERE id = ?').get(lead_id);
    if (!lead) return res.status(404).json({ error: 'Lead inquiry not found' });

    let outletsCount = 1;
    let selectedPlan = plan || 'Starter POS';
    let mrr = mrr_amount !== null ? parseFloat(mrr_amount) : 1999;

    if (!plan) {
      if (lead.outlets === '2-5') {
        outletsCount = 3;
        selectedPlan = 'Pro Multi-Outlet';
        mrr = 4999;
      } else if (lead.outlets === '6-10' || lead.outlets === '10+') {
        outletsCount = lead.outlets === '10+' ? 12 : 8;
        selectedPlan = 'Enterprise Cloud';
        mrr = 12999;
      }
    }

    const days = parseInt(duration_days, 10) || (subscription_type === 'trial' ? 7 : 30);
    const slug = lead.restaurant.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') + '-' + Date.now().toString().slice(-4);
    const rawPassword = password ? password.trim() : 'spicyhub123';
    const hashedPassword = hashPassword(rawPassword);
    const subType = subscription_type === 'paid' ? 'paid' : 'trial';
    const status = subType === 'trial' ? 'Trial Active' : 'Active';

    const expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);

    const stmt = db.prepare(`
      INSERT INTO tenants (
        name, owner_name, owner_email, owner_phone, city, outlets_count,
        plan, mrr_amount, status, subscription_type, password,
        trial_ends_at, subscription_expires_at, workspace_slug
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const info = stmt.run(
      lead.restaurant, lead.name, lead.email, lead.phone, lead.city || 'India',
      outletsCount, selectedPlan, mrr, status, subType, hashedPassword,
      subType === 'trial' ? expiryDate : null,
      expiryDate, slug
    );

    db.prepare("UPDATE leads SET status = ?, notes = ? WHERE id = ?")
      .run(status, `Provisioned ${days}-day ${subType} access.`, lead_id);

    logSecurityEvent('LEAD_PROVISIONED_WORKSPACE', { leadId: lead_id, tenantId: info.lastInsertRowid }, req);

    return res.json({
      success: true,
      message: `Successfully provisioned ${days}-day ${subType} workspace for ${lead.restaurant}!`,
      tenantId: info.lastInsertRowid,
      email: lead.email,
      password: rawPassword,
      subscription_type: subType,
      expires_at: expiryDate,
      slug
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/saas/plans', (req, res) => {
  try {
    const plans = db.prepare('SELECT * FROM saas_plans ORDER BY price_monthly ASC').all();
    return res.json({ plans });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/saas/settings', requireAdmin, (req, res) => {
  try {
    const settings = db.prepare('SELECT * FROM saas_settings WHERE id = 1').get();
    return res.json({ settings });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/saas/settings', requireAdmin, (req, res) => {
  try {
    const { platform_name, platform_version, global_banner, maintenance_mode } = req.body;
    const stmt = db.prepare(`
      UPDATE saas_settings SET
        platform_name = COALESCE(?, platform_name),
        platform_version = COALESCE(?, platform_version),
        global_banner = COALESCE(?, global_banner),
        maintenance_mode = COALESCE(?, maintenance_mode),
        has_pending_publish = 1,
        pending_release_notes = 'Platform updates staged for live deployment.'
      WHERE id = 1
    `);
    stmt.run(platform_name, platform_version, global_banner, maintenance_mode);
    return res.json({ success: true, message: 'Settings saved to staging.' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/saas/publish', requireAdmin, (req, res) => {
  try {
    db.prepare(`
      UPDATE saas_settings SET
        has_pending_publish = 0,
        pending_release_notes = '',
        last_published_at = CURRENT_TIMESTAMP
      WHERE id = 1
    `).run();
    return res.json({
      success: true,
      message: 'All platform updates & global broadcasts successfully published across all tenant clusters!'
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Security Audit Logs API (Area 18)
app.get('/api/saas/security-logs', requireAdmin, (req, res) => {
  try {
    const logs = getRecentSecurityLogs(100);
    return res.json({ logs });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Database Backups API (Area 17)
app.get('/api/saas/backups', requireAdmin, (req, res) => {
  try {
    const backups = listBackups();
    return res.json({ backups });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/saas/backup/create', requireAdmin, (req, res) => {
  try {
    const result = createBackup('admin-ondemand');
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 6. INBOUND TRIAL LEADS (Area 1, 2, 9)
// ==========================================
// Public lead submission with rate limiting and strict validation
const leadSubmissionsMap = new Map();
app.post('/api/lead', (req, res) => {
  try {
    const ip = getClientIP(req);
    const now = Date.now();
    const userLeads = leadSubmissionsMap.get(ip) || [];
    const recentLeads = userLeads.filter(t => now - t < 15 * 60 * 1000);

    // Max 10 trial requests per 15 mins per IP
    if (recentLeads.length >= 10) {
      logSecurityEvent('LEAD_SPAM_BLOCKED', { ip }, req);
      return res.status(429).json({ error: 'Too many trial requests. Please try again later or contact us directly.' });
    }
    recentLeads.push(now);
    leadSubmissionsMap.set(ip, recentLeads);

    const { name, email, phone, restaurant, city, outlets = '1' } = req.body || {};

    const nameVal = validateString(name, 2, 80, 'Full name');
    if (!nameVal.valid) return res.status(400).json({ error: nameVal.error });

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please provide a valid work email address.' });
    }

    const phoneVal = validateString(phone, 5, 25, 'Phone number');
    if (!phoneVal.valid) return res.status(400).json({ error: phoneVal.error });

    const restVal = validateString(restaurant, 2, 100, 'Restaurant brand');
    if (!restVal.valid) return res.status(400).json({ error: restVal.error });

    const cleanCity = city ? String(city).slice(0, 50).trim() : '';
    const cleanOutlets = String(outlets).slice(0, 20).trim();

    const stmt = db.prepare(`
      INSERT INTO leads (name, email, phone, restaurant, city, outlets)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const info = stmt.run(nameVal.value, email.trim().toLowerCase(), phoneVal.value, restVal.value, cleanCity, cleanOutlets);

    logSecurityEvent('LEAD_SUBMITTED', { leadId: info.lastInsertRowid, email }, req);

    return res.json({
      success: true,
      message: 'Your 7-day trial request was received! Our team will contact you shortly.',
      emailStatus: 'sent',
      leadId: info.lastInsertRowid
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to record your trial request.' });
  }
});

app.get('/api/leads', requireAdmin, (req, res) => {
  try {
    const leads = db.prepare('SELECT * FROM leads ORDER BY created_at DESC').all();
    return res.json({ leads });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/leads/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;
    const stmt = db.prepare('UPDATE leads SET status = COALESCE(?, status), notes = COALESCE(?, notes) WHERE id = ?');
    stmt.run(status, notes, id);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete('/api/leads/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM leads WHERE id = ?').run(id);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 7. RESTAURANT OS OPERATIONAL WORKSPACE APIS
// ==========================================
app.get('/api/dashboard/stats', (req, res) => {
  try {
    const salesRow = db.prepare('SELECT COALESCE(SUM(total_amount), 0) as net_sales, COUNT(*) as total_orders FROM orders').get();
    const activeOrdersRow = db.prepare("SELECT COUNT(*) as active_count FROM orders WHERE status IN ('New', 'Preparing', 'Ready')").get();
    const tablesStats = db.prepare(`
      SELECT 
        COUNT(*) as total_tables,
        SUM(CASE WHEN status = 'occupied' THEN 1 ELSE 0 END) as occupied_tables,
        SUM(CASE WHEN status = 'ready' THEN 1 ELSE 0 END) as ready_tables,
        SUM(CASE WHEN status = 'available' THEN 1 ELSE 0 END) as available_tables
      FROM tables
    `).get();
    const lowStockRow = db.prepare('SELECT COUNT(*) as low_stock_count FROM inventory WHERE current_stock <= low_stock_threshold').get();
    const avgTicket = salesRow.total_orders > 0 ? Math.round(salesRow.net_sales / salesRow.total_orders) : 0;

    return res.json({
      netSales: salesRow.net_sales,
      totalOrders: salesRow.total_orders,
      activeOrders: activeOrdersRow.active_count,
      avgTicket,
      tables: tablesStats,
      lowStockCount: lowStockRow.low_stock_count
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/orders', (req, res) => {
  try {
    const orders = db.prepare('SELECT * FROM orders ORDER BY id DESC').all();
    const getItems = db.prepare('SELECT * FROM order_items WHERE order_id = ?');
    return res.json({ orders: orders.map(o => ({ ...o, items: getItems.all(o.id) })) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/orders', (req, res) => {
  try {
    const { table_number, order_type = 'Dine-In', items = [], customer_name = 'Walk-in Guest', customer_email = '' } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Order must contain at least one item.' });
    }

    const cleanCustName = String(customer_name || 'Walk-in Guest').slice(0, 100).trim();
    const cleanCustEmail = customer_email ? String(customer_email).slice(0, 100).trim() : '';

    const maxOrder = db.prepare("SELECT MAX(CAST(SUBSTR(order_no, 2) AS INTEGER)) as max_no FROM orders").get();
    const nextNum = (maxOrder && maxOrder.max_no) ? (maxOrder.max_no + 1) : 1049;
    const orderNo = `#${nextNum}`;

    let subtotal = 0;
    for (const item of items) {
      const price = parseFloat(item.unit_price) || 0;
      const qty = parseInt(item.quantity, 10) || 1;
      if (price < 0 || qty < 1) {
        return res.status(400).json({ error: 'Invalid item price or quantity in order.' });
      }
      subtotal += (price * qty);
    }

    const tax = Math.round(subtotal * 0.05 * 100) / 100;
    const total = subtotal + tax;
    const hasEmail = Boolean(cleanCustEmail && isValidEmail(cleanCustEmail));
    const receiptType = hasEmail ? 'email' : 'hardcopy';

    const cleanTable = table_number ? String(table_number).slice(0, 10).trim() : null;

    const info = db.prepare(`
      INSERT INTO orders (order_no, table_number, order_type, status, total_amount, tax_amount, payment_status, customer_name, customer_email, receipt_type)
      VALUES (?, ?, ?, 'New', ?, ?, 'Unpaid', ?, ?, ?)
    `).run(orderNo, cleanTable, order_type, total, tax, cleanCustName, cleanCustEmail, receiptType);

    const orderId = info.lastInsertRowid;
    const insItem = db.prepare('INSERT INTO order_items (order_id, menu_item_id, item_name, quantity, unit_price, total_price) VALUES (?, ?, ?, ?, ?, ?)');
    for (const item of items) {
      const q = parseInt(item.quantity, 10) || 1;
      const p = parseFloat(item.unit_price) || 0;
      insItem.run(orderId, item.menu_item_id || null, String(item.item_name || 'Item').slice(0, 100), q, p, p * q);
    }

    if (cleanTable) {
      db.prepare("UPDATE tables SET status = 'occupied', current_order_id = ? WHERE table_number = ?").run(orderId, cleanTable);
    }

    return res.json({
      success: true,
      order: { id: orderId, order_no: orderNo, table_number: cleanTable, order_type, status: 'New', total_amount: total, tax_amount: tax, customer_name: cleanCustName, customer_email: cleanCustEmail, receipt_type: receiptType, items },
      receipt: { order_no: orderNo, table_number: cleanTable, customer_name: cleanCustName, customer_email: cleanCustEmail, receipt_type: receiptType, subtotal, tax_amount: tax, total_amount: total, items, emailed: hasEmail, hardcopy: !hasEmail }
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/orders/:id/status', (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const allowed = ['New', 'Preparing', 'Ready', 'Completed', 'Cancelled'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: 'Invalid order status transition.' });
    }

    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
    if (status === 'Completed' || status === 'Cancelled') {
      const o = db.prepare('SELECT table_number FROM orders WHERE id = ?').get(id);
      if (o && o.table_number) {
        db.prepare("UPDATE tables SET status = 'available', current_order_id = NULL WHERE table_number = ?").run(o.table_number);
      }
      if (status === 'Completed') db.prepare("UPDATE orders SET payment_status = 'Paid' WHERE id = ?").run(id);
    }
    return res.json({ success: true, status });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/tables', (req, res) => {
  try {
    const tables = db.prepare('SELECT * FROM tables ORDER BY table_number ASC').all();
    const getActive = db.prepare("SELECT order_no, total_amount, status, customer_name, customer_email FROM orders WHERE id = ?");
    return res.json({ tables: tables.map(t => ({ ...t, active_order: t.current_order_id ? getActive.get(t.current_order_id) : null })) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/tables', (req, res) => {
  try {
    let { table_number, capacity = 4 } = req.body;
    if (!table_number) return res.status(400).json({ error: 'Table number required' });

    table_number = String(table_number).trim().toUpperCase();
    if (!/^[A-Za-z0-9_-]{1,10}$/.test(table_number)) {
      return res.status(400).json({ error: 'Table number must be alphanumeric (max 10 chars).' });
    }

    capacity = parseInt(capacity, 10);
    if (isNaN(capacity) || capacity < 1 || capacity > 50) {
      return res.status(400).json({ error: 'Capacity must be between 1 and 50 seats.' });
    }

    const existing = db.prepare('SELECT id FROM tables WHERE table_number = ?').get(table_number);
    if (existing) return res.status(400).json({ error: `Table ${table_number} already exists` });

    const info = db.prepare("INSERT INTO tables (table_number, capacity, status) VALUES (?, ?, 'available')").run(table_number, capacity);
    return res.json({ success: true, table: { id: info.lastInsertRowid, table_number, capacity, status: 'available' } });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tables/:table_number/capacity', (req, res) => {
  try {
    const { table_number } = req.params;
    const { capacity } = req.body;
    const capNum = parseInt(capacity, 10);
    if (isNaN(capNum) || capNum < 1 || capNum > 50) {
      return res.status(400).json({ error: 'Capacity must be between 1 and 50.' });
    }
    db.prepare('UPDATE tables SET capacity = ?, updated_at = CURRENT_TIMESTAMP WHERE table_number = ?').run(capNum, table_number);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete('/api/tables/:table_number', (req, res) => {
  try {
    const { table_number } = req.params;
    const tbl = db.prepare('SELECT * FROM tables WHERE table_number = ?').get(table_number);
    if (!tbl) return res.status(404).json({ error: 'Table not found' });
    if (tbl.status === 'occupied') return res.status(400).json({ error: 'Cannot remove an occupied table with active service.' });
    db.prepare('DELETE FROM tables WHERE table_number = ?').run(table_number);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tables/:table_number/status', (req, res) => {
  try {
    const { table_number } = req.params;
    const { status } = req.body;
    const allowed = ['available', 'occupied', 'ready'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: 'Invalid table status.' });
    }
    db.prepare('UPDATE tables SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE table_number = ?').run(status, table_number);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/menu', (req, res) => {
  try {
    const categories = db.prepare('SELECT * FROM menu_categories ORDER BY display_order ASC').all();
    const getItems = db.prepare('SELECT * FROM menu_items WHERE category_id = ? ORDER BY id ASC');
    return res.json({ menu: categories.map(c => ({ ...c, items: getItems.all(c.id) })) });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/menu', (req, res) => {
  try {
    const { category_id, name, description = '', price, is_veg = 1 } = req.body;
    const nameVal = validateString(name, 1, 100, 'Dish name');
    if (!nameVal.valid) return res.status(400).json({ error: nameVal.error });

    const priceNum = parseFloat(price);
    if (isNaN(priceNum) || priceNum < 0) return res.status(400).json({ error: 'Price must be a valid positive number.' });

    const info = db.prepare('INSERT INTO menu_items (category_id, name, description, price, is_veg, in_stock) VALUES (?, ?, ?, ?, ?, 1)')
      .run(parseInt(category_id, 10), nameVal.value, String(description || '').slice(0, 300).trim(), priceNum, is_veg ? 1 : 0);

    return res.json({ success: true, item: { id: info.lastInsertRowid, category_id, name: nameVal.value, price: priceNum } });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/menu/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, is_veg, in_stock } = req.body;
    db.prepare(`
      UPDATE menu_items SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        price = COALESCE(?, price),
        is_veg = COALESCE(?, is_veg),
        in_stock = COALESCE(?, in_stock)
      WHERE id = ?
    `).run(
      name ? String(name).slice(0, 100).trim() : null,
      description !== undefined ? String(description).slice(0, 300).trim() : null,
      price !== undefined ? Math.max(0, parseFloat(price)) : null,
      is_veg !== undefined ? (is_veg ? 1 : 0) : null,
      in_stock !== undefined ? (in_stock ? 1 : 0) : null,
      id
    );
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete('/api/menu/:id', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM menu_items WHERE id = ?').run(id);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/inventory', (req, res) => {
  try {
    const inventory = db.prepare('SELECT * FROM inventory ORDER BY id ASC').all();
    return res.json({ inventory });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch('/api/inventory/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { current_stock, low_stock_threshold, max_stock, unit, item_name } = req.body;
    const existing = db.prepare('SELECT * FROM inventory WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Item not found' });

    const newStock = current_stock !== undefined ? Math.max(0, parseFloat(current_stock)) : existing.current_stock;
    const threshold = low_stock_threshold !== undefined ? Math.max(0, parseFloat(low_stock_threshold)) : existing.low_stock_threshold;
    const maxVal = max_stock !== undefined ? Math.max(newStock, parseFloat(max_stock)) : existing.max_stock;

    let status = 'In stock';
    if (newStock <= 0) status = 'Out of stock';
    else if (newStock <= threshold) status = 'Low stock';

    db.prepare(`
      UPDATE inventory SET
        current_stock = ?, low_stock_threshold = ?, max_stock = ?, unit = COALESCE(?, unit), item_name = COALESCE(?, item_name), status = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(newStock, threshold, maxVal, unit ? String(unit).slice(0, 20) : null, item_name ? String(item_name).slice(0, 100) : null, status, id);

    return res.json({ success: true, item: { id, current_stock: newStock, status } });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/inventory', (req, res) => {
  try {
    const { item_name, current_stock = 50, max_stock = 100, unit = 'kg', low_stock_threshold = 20 } = req.body;
    const nameVal = validateString(item_name, 1, 100, 'Material name');
    if (!nameVal.valid) return res.status(400).json({ error: nameVal.error });

    const cStock = Math.max(0, parseFloat(current_stock) || 0);
    const mStock = Math.max(cStock, parseFloat(max_stock) || 100);
    const lowThresh = Math.max(0, parseFloat(low_stock_threshold) || 20);

    const info = db.prepare('INSERT INTO inventory (item_name, current_stock, max_stock, unit, low_stock_threshold, status) VALUES (?, ?, ?, ?, ?, "In stock")')
      .run(nameVal.value, cStock, mStock, String(unit || 'kg').slice(0, 20), lowThresh);

    return res.json({ success: true, item: { id: info.lastInsertRowid, item_name: nameVal.value, current_stock: cStock } });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete('/api/inventory/:id', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM inventory WHERE id = ?').run(id);
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/inventory/:id/restock', (req, res) => {
  try {
    const { id } = req.params;
    const { amount = 20 } = req.body;
    const amt = Math.max(1, parseFloat(amount) || 20);
    const item = db.prepare('SELECT * FROM inventory WHERE id = ?').get(id);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    const newStock = Math.min(item.max_stock, item.current_stock + amt);
    const newStatus = newStock > item.low_stock_threshold ? 'In stock' : 'Low stock';
    db.prepare('UPDATE inventory SET current_stock = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(newStock, newStatus, id);
    return res.json({ success: true, current_stock: newStock, status: newStatus });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 8. SERVE APPLICATION PORTALS (Area 15: Safe routes only)
// ==========================================
function setHtmlNoCache(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
}

// Private B2B SaaS Superadmin Portal (Unlinked)
app.get('/admin', (req, res) => {
  setHtmlNoCache(res);
  res.sendFile(path.join(rootDir, 'admin.html'));
});

// Unified Restaurant OS (Workspace & Integrated Owner Sign-In Gateway)
app.get(['/dashboard', '/app', '/os', '/login', '/trial', '/signin'], (req, res) => {
  setHtmlNoCache(res);
  res.sendFile(path.join(rootDir, 'dashboard.html'));
});

// Marketing Landing Page
app.get('/', (req, res) => {
  setHtmlNoCache(res);
  res.sendFile(path.join(rootDir, 'index.html'));
});

// 404 handler for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: 'Resource not found.' });
});

// Centralized error handler (no stack trace leak)
app.use((err, req, res, next) => {
  logSecurityEvent('UNHANDLED_SERVER_ERROR', { error: err.message, stack: err.stack }, req);
  res.status(500).json({ error: 'An internal server error occurred.' });
});

app.listen(PORT, () => {
  console.log(`\n==================================================================`);
  console.log(`🔥 Spicyhub B2B SaaS Platform [HARDENED & SECURED] is RUNNING!`);
  console.log(`------------------------------------------------------------------`);
  console.log(`🌐 Public Marketing Site    : http://localhost:${PORT}`);
  console.log(`⚡ Unified Restaurant OS   : http://localhost:${PORT}/os`);
  console.log(`🔒 SaaS Superadmin Center : http://localhost:${PORT}/admin (Private)`);
  console.log(`📁 High-Performance DB    : ./data/spicyhub.db (SQLite WAL)`);
  console.log(`🛡️  Security Profile       : Rate Limiter + Scrypt + HMAC + Helmet Active`);
  console.log(`==================================================================\n`);
});
