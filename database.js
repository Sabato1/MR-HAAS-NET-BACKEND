const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Njia ya kufungua database ndani ya folda ya project
const dbPath = path.resolve(__dirname, 'wisp.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Hitilafu wakati wa kufungua database:', err.message);
    } else {
        console.log('Imeunganishwa vizuri na database ya SQLite.');
    }
});

// Kutengeneza majedwali ya msingi kama hayapo
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT,
        name TEXT,
        host TEXT,
        user TEXT,
        password TEXT,
        port INTEGER,
        type TEXT
    )`);
});

module.exports = db;
