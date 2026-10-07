'use strict';
/* Makes a consistent copy of the database and uploads while the portal is running.
   Usage: node backup.js [target-folder]   (default: ./backups/<timestamp>) */
const fs = require('node:fs'), path = require('node:path');
process.removeAllListeners('warning');
const { DatabaseSync } = require('node:sqlite');
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const out = path.resolve(process.argv[2] || path.join(__dirname, 'backups', stamp));
fs.mkdirSync(out, { recursive: true });
const dbFile = path.join(DATA_DIR, 'jlpl.db');
if (!fs.existsSync(dbFile)) { console.error('No database found at ' + dbFile + '. Set DATA_DIR to the portal data folder.'); process.exit(1); }
const db = new DatabaseSync(dbFile);
db.exec(`VACUUM INTO '${path.join(out, 'jlpl.db').replace(/'/g, "''")}'`);
fs.cpSync(path.join(DATA_DIR, 'uploads'), path.join(out, 'uploads'), { recursive: true });
console.log('Backup written to ' + out);
