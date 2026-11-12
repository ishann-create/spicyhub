import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dataDir = path.join(__dirname, '..', 'data');
const backupDir = path.join(dataDir, 'backups');
const dbPath = path.join(dataDir, 'spicyhub.db');

const RETENTION_DAYS = parseInt(process.env.BACKUP_RETENTION_DAYS, 10) || 7;

// Ensure backup directory exists
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
}

/**
 * Creates a point-in-time timestamped backup of the SQLite database
 */
export function createBackup(reason = 'scheduled') {
  try {
    if (!fs.existsSync(dbPath)) {
      return { success: false, error: 'Source database file not found' };
    }

    const now = new Date();
    const dateStr = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const backupFileName = `spicyhub-backup-${dateStr}-${reason}.db`;
    const targetPath = path.join(backupDir, backupFileName);

    // Copy DB file atomically
    fs.copyFileSync(dbPath, targetPath);

    // Also copy WAL if present
    const walPath = `${dbPath}-wal`;
    if (fs.existsSync(walPath)) {
      try {
        fs.copyFileSync(walPath, `${targetPath}-wal`);
      } catch (e) {}
    }

    const stats = fs.statSync(targetPath);

    // Enforce retention cleanup
    pruneOldBackups();

    return {
      success: true,
      backupFile: backupFileName,
      sizeBytes: stats.size,
      createdAt: now.toISOString()
    };
  } catch (err) {
    console.error('Database backup failure:', err);
    return { success: false, error: err.message };
  }
}

/**
 * Deletes backups older than RETENTION_DAYS
 */
export function pruneOldBackups() {
  try {
    if (!fs.existsSync(backupDir)) return;
    const files = fs.readdirSync(backupDir);
    const now = Date.now();
    const maxAgeMs = RETENTION_DAYS * 24 * 60 * 60 * 1000;

    for (const file of files) {
      if (!file.endsWith('.db')) continue;
      const filePath = path.join(backupDir, file);
      const stat = fs.statSync(filePath);
      if (now - stat.mtimeMs > maxAgeMs) {
        fs.unlinkSync(filePath);
        // Also remove associated wal if any
        if (fs.existsSync(`${filePath}-wal`)) {
          fs.unlinkSync(`${filePath}-wal`);
        }
        console.log(`[BACKUP RETENTION] Pruned outdated database snapshot: ${file}`);
      }
    }
  } catch (e) {
    console.warn('Backup pruning warning:', e);
  }
}

/**
 * Lists available backups with metadata
 */
export function listBackups() {
  try {
    if (!fs.existsSync(backupDir)) return [];
    const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.db'));
    return files.map(file => {
      const p = path.join(backupDir, file);
      const s = fs.statSync(p);
      return {
        fileName: file,
        sizeBytes: s.size,
        createdAt: s.mtime.toISOString()
      };
    }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  } catch (e) {
    return [];
  }
}

// Schedule automated daily backup (every 24 hours)
setInterval(() => {
  createBackup('automated-daily');
}, 24 * 60 * 60 * 1000);
