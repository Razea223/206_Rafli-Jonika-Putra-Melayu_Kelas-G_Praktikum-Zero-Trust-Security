const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const db = new Database('zero-trust.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL, nim TEXT UNIQUE, nama TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, device_id TEXT NOT NULL,
 UNIQUE(user_id, device_id), FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS classes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, nama TEXT NOT NULL, dosen_id INTEGER NOT NULL,
 FOREIGN KEY(dosen_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS grades (
 id INTEGER PRIMARY KEY AUTOINCREMENT, class_id INTEGER NOT NULL, nim TEXT NOT NULL,
 nilai REAL NOT NULL, final INTEGER DEFAULT 0,
 FOREIGN KEY(class_id) REFERENCES classes(id)
);
CREATE TABLE IF NOT EXISTS transcripts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, nim TEXT NOT NULL, class_id INTEGER NOT NULL,
 nilai REAL NOT NULL, updated_at TEXT NOT NULL, UNIQUE(nim, class_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL, revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, subject TEXT, endpoint TEXT,
 device TEXT, result TEXT NOT NULL, reason TEXT NOT NULL
);
`);

function seed() {
 const count = db.prepare('SELECT COUNT(*) n FROM users').get().n;
 if (count) return;
 const users = [
  ['admin','Admin123!','admin',null,'Administrator'],
  ['dosen1','Dosen123!','dosen',null,'Dosen Andi'],
  ['dosen2','Dosen123!','dosen',null,'Dosen Budi'],
  ['mhs1','Mhs123!','mahasiswa','247001','Mahasiswa Satu'],
  ['mhs2','Mhs123!','mahasiswa','247002','Mahasiswa Dua'],
  ['mhs3','Mhs123!','mahasiswa','247003','Mahasiswa Tiga']
 ];
 const insert = db.prepare('INSERT INTO users(username,password_hash,role,nim,nama) VALUES(?,?,?,?,?)');
 for (const u of users) insert.run(u[0], bcrypt.hashSync(u[1], 10), u[2], u[3], u[4]);
 const id = name => db.prepare('SELECT id FROM users WHERE username=?').get(name).id;
 const device = db.prepare('INSERT INTO devices(user_id,device_id) VALUES(?,?)');
 for (const [name, dev] of [['admin','dev-admin-01'],['dosen1','dev-dosen1-01'],['dosen2','dev-dosen2-01'],['mhs1','dev-mhs1-01'],['mhs2','dev-mhs2-01'],['mhs3','dev-mhs3-01']]) device.run(id(name),dev);
 const cls = db.prepare('INSERT INTO classes(nama,dosen_id) VALUES(?,?)');
 cls.run('Algoritma dan Pemrograman',id('dosen1'));
 cls.run('Keamanan Informasi',id('dosen2'));
 const g = db.prepare('INSERT INTO grades(class_id,nim,nilai,final) VALUES(?,?,?,0)');
 g.run(1,'247001',85); g.run(1,'247002',90); g.run(2,'247003',88);
}
seed();
module.exports = db;
