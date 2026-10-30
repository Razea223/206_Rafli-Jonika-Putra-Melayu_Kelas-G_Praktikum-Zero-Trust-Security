const jwt = require('jsonwebtoken');
const db = require('./db');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-this-jwt-secret';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dev-only-change-this-gateway-secret';

function verifyServiceRequest(req, res, next) {
  if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) {
    return res.status(403).json({ error: 'Forbidden', reason: 'Gateway secret tidak valid' });
  }
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Token wajib ada' });
  try {
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    if (!['user','service'].includes(payload.tokenType)) throw new Error('Tipe token tidak valid');
    req.auth = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token tidak valid atau kedaluwarsa' });
  }
}
function logAudit(subject, endpoint, device, result, reason) {
  db.prepare('INSERT INTO audit_logs(time,subject,endpoint,device,result,reason) VALUES(?,?,?,?,?,?)')
    .run(new Date().toISOString(), subject || 'anonymous', endpoint, device || '-', result, reason);
}
module.exports = { jwt, db, JWT_SECRET, GATEWAY_SECRET, verifyServiceRequest, logAudit };
