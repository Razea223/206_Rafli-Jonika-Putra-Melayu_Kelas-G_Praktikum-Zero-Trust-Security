const db = require('./db');

function decide({ user, method, path, deviceId, now = new Date() }) {
  if (!user) return { allow: false, reason: 'Token user tidak tersedia' };
  if (user.tokenType === 'service') {
    if (user.role !== 'service') return { allow: false, reason: 'Role service tidak valid' };
    if (path === '/transkrip/sinkron' && method === 'POST') return { allow: true, reason: 'Token service untuk sinkronisasi' };
    return { allow: false, reason: 'Token service hanya boleh sinkronisasi transkrip' };
  }
  const dbUser = db.prepare('SELECT * FROM users WHERE id=?').get(user.uid);
  if (!dbUser) return { allow: false, reason: 'User tidak ditemukan' };
  const device = db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(dbUser.id, deviceId || '');
  if (!device) return { allow: false, reason: 'Device tidak terdaftar untuk user ini' };

  if (path === '/nilai' && method === 'GET') {
    if (dbUser.role === 'mahasiswa' || dbUser.role === 'dosen') return { allow: true, reason: 'Role boleh melihat nilai; data difilter oleh service' };
    return { allow: false, reason: 'Role tidak boleh melihat nilai' };
  }
  const update = path.match(/^\/nilai\/(\d+)$/) && method === 'PUT';
  const finalize = path.match(/^\/kelas\/(\d+)\/finalisasi$/) && method === 'POST';
  if (update || finalize) {
    if (dbUser.role !== 'dosen') return { allow: false, reason: 'Hanya dosen boleh mengubah/finalisasi nilai' };
    const classId = update
      ? (db.prepare('SELECT class_id FROM grades WHERE id=?').get(Number(path.match(/^\/nilai\/(\d+)$/)[1]) || 0) || {}).class_id
      : Number(path.match(/^\/kelas\/(\d+)\/finalisasi$/)[1]);
    const cls = db.prepare('SELECT dosen_id FROM classes WHERE id=?').get(classId || -1);
    if (!cls || cls.dosen_id !== dbUser.id) return { allow: false, reason: 'Dosen bukan pengampu kelas tersebut' };
    const start = Number(process.env.ACCESS_START_HOUR || 7);
    const end = Number(process.env.ACCESS_END_HOUR || 21);
    const hour = now.getHours();
    if (hour < start || hour >= end) return { allow: false, reason: `Di luar jam akses ${start}:00-${end}:00` };
    if (update) {
      const gradeId = Number(path.match(/^\/nilai\/(\d+)$/)[1]);
      const grade = db.prepare('SELECT final FROM grades WHERE id=?').get(gradeId);
      if (!grade || grade.final) return { allow: false, reason: 'Nilai tidak ditemukan atau sudah final' };
    }
    return { allow: true, reason: 'Dosen pengampu, device valid, dan dalam jam akses' };
  }
  const transcript = path.match(/^\/transkrip\/([^/]+)$/) && method === 'GET';
  if (transcript) {
    if (dbUser.role === 'admin') return { allow: true, reason: 'Admin boleh melihat semua transkrip' };
    if (dbUser.role === 'mahasiswa' && dbUser.nim === decodeURIComponent(path.match(/^\/transkrip\/([^/]+)$/)[1])) return { allow: true, reason: 'Mahasiswa mengakses transkrip sendiri' };
    return { allow: false, reason: 'Transkrip hanya boleh dilihat pemiliknya atau admin' };
  }
  return { allow: false, reason: 'Endpoint atau metode tidak diizinkan oleh kebijakan' };
}
module.exports = { decide };
