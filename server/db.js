import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hashPassword } from './security.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'spicyhub.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode for high concurrency & performance
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// Initialize database schema
export function initDB() {
  db.exec(`
    -- 1. B2B SAAS LEADS & TRIAL INQUIRIES (From Homepage Modal)
    CREATE TABLE IF NOT EXISTS leads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      restaurant TEXT NOT NULL,
      city TEXT NOT NULL,
      outlets TEXT NOT NULL DEFAULT '1',
      status TEXT NOT NULL DEFAULT 'New',
      notes TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- 2. B2B TENANT RESTAURANTS (Active Clients on Spicyhub OS)
    CREATE TABLE IF NOT EXISTS tenants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      owner_name TEXT NOT NULL,
      owner_email TEXT NOT NULL,
      owner_phone TEXT NOT NULL,
      city TEXT NOT NULL,
      outlets_count INTEGER NOT NULL DEFAULT 1,
      plan TEXT NOT NULL DEFAULT 'Pro Multi-Outlet',
      mrr_amount REAL NOT NULL DEFAULT 4999,
      status TEXT NOT NULL DEFAULT 'Active',
      subscription_type TEXT NOT NULL DEFAULT 'trial',
      password TEXT NOT NULL DEFAULT 'spicyhub123',
      trial_ends_at DATETIME,
      subscription_expires_at DATETIME,
      workspace_slug TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- 3. B2B SAAS SUBSCRIPTION PLANS
    CREATE TABLE IF NOT EXISTS saas_plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      price_monthly REAL NOT NULL,
      outlet_limit TEXT NOT NULL,
      features TEXT NOT NULL,
      is_popular INTEGER DEFAULT 0
    );

    -- 4. B2B SAAS PLATFORM CONFIG & STAGING
    CREATE TABLE IF NOT EXISTS saas_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      platform_name TEXT DEFAULT 'Spicyhub Cloud OS',
      platform_version TEXT DEFAULT 'v2.4.2-enterprise',
      global_banner TEXT DEFAULT 'All Spicyhub cloud clusters operational across AP-South (Mumbai).',
      maintenance_mode INTEGER DEFAULT 0,
      has_pending_publish INTEGER DEFAULT 0,
      pending_release_notes TEXT DEFAULT '',
      last_published_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- 5. RESTAURANT TENANT OPERATIONAL WORKSPACE (Sample Tenant Jaipur Outlet)
    CREATE TABLE IF NOT EXISTS tables (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      table_number TEXT UNIQUE NOT NULL,
      capacity INTEGER DEFAULT 4,
      status TEXT NOT NULL DEFAULT 'available',
      current_order_id INTEGER,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS menu_categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      display_order INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS menu_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category_id INTEGER,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      is_veg INTEGER DEFAULT 1,
      in_stock INTEGER DEFAULT 1,
      FOREIGN KEY (category_id) REFERENCES menu_categories(id)
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_no TEXT UNIQUE NOT NULL,
      table_number TEXT,
      order_type TEXT NOT NULL DEFAULT 'Dine-In',
      status TEXT NOT NULL DEFAULT 'New',
      total_amount REAL NOT NULL DEFAULT 0,
      tax_amount REAL NOT NULL DEFAULT 0,
      payment_status TEXT NOT NULL DEFAULT 'Unpaid',
      payment_method TEXT,
      customer_name TEXT,
      customer_email TEXT DEFAULT '',
      receipt_type TEXT DEFAULT 'hardcopy',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      menu_item_id INTEGER,
      item_name TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      unit_price REAL NOT NULL,
      total_price REAL NOT NULL,
      notes TEXT,
      FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_name TEXT UNIQUE NOT NULL,
      current_stock REAL NOT NULL,
      max_stock REAL NOT NULL DEFAULT 100,
      unit TEXT NOT NULL DEFAULT 'kg',
      low_stock_threshold REAL NOT NULL DEFAULT 20,
      status TEXT NOT NULL DEFAULT 'In stock',
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Run migrations safely
  try { db.exec("ALTER TABLE orders ADD COLUMN customer_email TEXT DEFAULT '';"); } catch(e) {}
  try { db.exec("ALTER TABLE orders ADD COLUMN receipt_type TEXT DEFAULT 'hardcopy';"); } catch(e) {}
  try { db.exec("ALTER TABLE tenants ADD COLUMN password TEXT DEFAULT 'spicyhub123';"); } catch(e) {}
  try { db.exec("ALTER TABLE tenants ADD COLUMN subscription_type TEXT DEFAULT 'trial';"); } catch(e) {}
  try { db.exec("ALTER TABLE tenants ADD COLUMN subscription_expires_at DATETIME;"); } catch(e) {}

  // Backfill expiry dates for any tenants that have NULL
  try {
    db.exec(`
      UPDATE tenants 
      SET subscription_expires_at = datetime('now', '+7 days') 
      WHERE subscription_expires_at IS NULL AND (status = 'Trial Active' OR subscription_type = 'trial');
    `);
    db.exec(`
      UPDATE tenants 
      SET subscription_expires_at = datetime('now', '+30 days') 
      WHERE subscription_expires_at IS NULL;
    `);
  } catch(e) {}

  // Migrate any existing plain-text passwords to secure salted scrypt hashes
  try {
    const tenants = db.prepare('SELECT id, password FROM tenants').all();
    const updateStmt = db.prepare('UPDATE tenants SET password = ? WHERE id = ?');
    for (const t of tenants) {
      if (t.password && !t.password.startsWith('scrypt:')) {
        const hashed = hashPassword(t.password);
        updateStmt.run(hashed, t.id);
      }
    }
  } catch(e) {}

  seedInitialData();
}

function seedInitialData() {
  // 1. Seed SaaS Platform Settings
  try {
    const s = db.prepare('SELECT id FROM saas_settings WHERE id = 1').get();
    if (!s) {
      db.exec(`
        INSERT INTO saas_settings (id, platform_name, platform_version, global_banner, has_pending_publish)
        VALUES (1, 'Spicyhub Cloud OS', 'v2.4.2-enterprise', 'All Spicyhub cloud clusters operational across AP-South (Mumbai).', 0);
      `);
    }
  } catch (e) {}

  // 2. Seed B2B SaaS Plans
  try {
    const planCount = db.prepare('SELECT COUNT(*) as c FROM saas_plans').get();
    if (planCount.c === 0) {
      const insPlan = db.prepare('INSERT INTO saas_plans (name, slug, price_monthly, outlet_limit, features, is_popular) VALUES (?, ?, ?, ?, ?, ?)');
      insPlan.run('Starter POS', 'starter', 1999, '1 Outlet', 'Billing & POS, Table Map, Basic Inventory, Daily Reports, Email Support', 0);
      insPlan.run('Pro Multi-Outlet', 'pro', 4999, '2–5 Outlets', 'Full POS + KDS, Live Chef Stock Audit, Multi-Outlet Aggregator, Auto E-Bill, 24/7 Priority Support', 1);
      insPlan.run('Enterprise Cloud', 'enterprise', 12999, '6+ Outlets (Unlimited)', 'Dedicated Cloud Cluster, Custom Integrations, Franchise Multi-Brand OS, Dedicated Account Manager, Custom SLA', 0);
    }
  } catch (e) {}

  // 3. Seed B2B Restaurant Tenants
  try {
    const tenantCount = db.prepare('SELECT COUNT(*) as c FROM tenants').get();
    if (tenantCount.c === 0) {
      const insTenant = db.prepare(`
        INSERT INTO tenants (name, owner_name, owner_email, owner_phone, city, outlets_count, plan, mrr_amount, status, subscription_type, password, subscription_expires_at, workspace_slug) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?), ?)
      `);
      const defaultHashedPassword = hashPassword('spicyhub123');
      insTenant.run('The Tandoor House', 'Aanya Sharma', 'aanya@tandoorhouse.in', '+91 98765 43210', 'Jaipur', 3, 'Pro Multi-Outlet', 4999, 'Active', 'paid', defaultHashedPassword, '+30 days', 'tandoor-house');
      insTenant.run('Spice Route Bistro', 'Karan Verma', 'karan@spiceroute.com', '+91 98111 22334', 'Bengaluru', 1, 'Starter POS', 1999, 'Active', 'paid', defaultHashedPassword, '+30 days', 'spice-route');
      insTenant.run('Royal Spice Dining', 'Rohit Mehra', 'rohit@royalspice.in', '+91 99887 76655', 'Delhi', 4, 'Pro Multi-Outlet', 4999, 'Trial Active', 'trial', defaultHashedPassword, '+7 days', 'royal-spice');
      insTenant.run('The Grand Haveli Heritage', 'Vikramaditya Singhania', 'vikram@singhaniagroup.in', '+91 98220 11223', 'Udaipur', 8, 'Enterprise Cloud', 12999, 'Trial Active', 'trial', defaultHashedPassword, '+7 days', 'grand-haveli');
      insTenant.run('Taj Pepper Heritage Bistro', 'Meera Singhania', 'meera@tajdining.com', '+91 97766 55443', 'Mumbai', 12, 'Enterprise Cloud', 12999, 'Trial Active', 'trial', defaultHashedPassword, '+7 days', 'taj-pepper');
      insTenant.run('Coastal Curry Kitchen', 'Arjun Kamath', 'arjun@coastalcurry.in', '+91 98450 67890', 'Goa', 2, 'Pro Multi-Outlet', 4999, 'Active', 'paid', defaultHashedPassword, '+30 days', 'coastal-curry');
    }
  } catch (e) {}

  // 4. Seed Inbound 7-Day Trial Leads (if empty)
  try {
    const leadCount = db.prepare('SELECT COUNT(*) as count FROM leads').get();
    if (leadCount.count === 0) {
      const insertLead = db.prepare('INSERT INTO leads (name, email, phone, restaurant, city, outlets, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
      insertLead.run('Aanya Sharma', 'aanya@tandoorhouse.in', '+91 98765 43210', 'The Tandoor House', 'Jaipur', '2-5', 'Trial Active', 'Requested multi-outlet KDS demo');
      insertLead.run('Karan Verma', 'karan@spiceroute.com', '+91 98111 22334', 'Spice Route Bistro', 'Bengaluru', '1', 'Contacted', 'Interested in inventory & table billing');
      insertLead.run('Rohit Mehra', 'rohit@royalspice.in', '+91 99887 76655', 'Royal Spice Dining', 'Delhi', '2-5', 'New', 'Submitted via website modal');
    }
  } catch (e) {}

  // 5. Seed sample tenant tables & menu if empty
  try {
    const tableCount = db.prepare('SELECT COUNT(*) as count FROM tables').get();
    if (tableCount.count === 0) {
      const insertTable = db.prepare('INSERT INTO tables (table_number, capacity, status) VALUES (?, ?, ?)');
      const initialTables = [
        ['T01', 4, 'occupied'],
        ['T02', 2, 'available'],
        ['T03', 6, 'occupied'],
        ['T04', 4, 'available'],
        ['T05', 2, 'ready'],
        ['T06', 4, 'available'],
        ['T07', 8, 'occupied'],
        ['T08', 4, 'available'],
        ['T09', 2, 'ready']
      ];
      for (const [tbl, cap, st] of initialTables) {
        insertTable.run(tbl, cap, st);
      }
    }

    const catCount = db.prepare('SELECT COUNT(*) as count FROM menu_categories').get();
    if (catCount.count === 0) {
      const insertCat = db.prepare('INSERT INTO menu_categories (name, display_order) VALUES (?, ?)');
      insertCat.run('Starters & Tandoor', 1);
      insertCat.run('Mains & Curries', 2);
      insertCat.run('Breads & Rice', 3);
      insertCat.run('Beverages & Desserts', 4);

      const categories = db.prepare('SELECT id, name FROM menu_categories').all();
      const catMap = Object.fromEntries(categories.map(c => [c.name, c.id]));

      const insertItem = db.prepare('INSERT INTO menu_items (category_id, name, description, price, is_veg, in_stock) VALUES (?, ?, ?, ?, ?, ?)');
      insertItem.run(catMap['Starters & Tandoor'], 'Paneer Tikka', 'Cottage cheese charred with spices.', 320, 1, 1);
      insertItem.run(catMap['Starters & Tandoor'], 'Masala Fries', 'Crispy spiced fries.', 180, 1, 1);
      insertItem.run(catMap['Mains & Curries'], 'Butter Chicken', 'Tender chicken in tomato gravy.', 440, 0, 1);
      insertItem.run(catMap['Breads & Rice'], 'Garlic Butter Naan', 'Fresh tandoor naan.', 85, 1, 1);
      insertItem.run(catMap['Beverages & Desserts'], 'Mango Lassi', 'Chilled sweet yogurt drink.', 140, 1, 1);
    }

    const invCount = db.prepare('SELECT COUNT(*) as count FROM inventory').get();
    if (invCount.count === 0) {
      const insertInv = db.prepare('INSERT INTO inventory (item_name, current_stock, max_stock, unit, low_stock_threshold, status) VALUES (?, ?, ?, ?, ?, ?)');
      insertInv.run('Paneer', 72, 100, 'kg', 20, 'In stock');
      insertInv.run('Cooking Oil', 22, 100, 'L', 30, 'Low stock');
      insertInv.run('Tomatoes', 56, 100, 'kg', 25, 'In stock');
    }
  } catch (e) {}
}

export default db;
