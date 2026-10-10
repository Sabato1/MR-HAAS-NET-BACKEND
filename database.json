const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Kuhakikisha database inatunzwa kwenye njia sahihi
const dbPath = path.resolve(__dirname, 'database.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Imeshindikana kuunganisha na Database:', err.message);
    } else {
        console.log('Imefanikiwa kuunganisha na SQLite Database kwenye:', dbPath);
    }
});

// Kutengeneza Jedwali la Vifaa (Devices Table)
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER NOT NULL,
        device_name TEXT NOT NULL,
        device_type TEXT NOT NULL,
        brand TEXT NOT NULL,
        ip_address TEXT,
        api_port INTEGER DEFAULT 8728,
        username TEXT,
        password TEXT,
        cloud_api_url TEXT,
        status TEXT DEFAULT 'offline',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) {
            // Hapa itatoa ujumbe kamili wa kosa lililotokea kwenye Database
            console.error("Hitilafu kamili katika kutengeneza jedwali la devices:", err.message);
        } else {
            console.log("Jedwali la devices limetengenezwa au tayari lipo.");
        }
    });
});

module.exports = db;
