const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const {
  createProxyMiddleware,
  fixRequestBody
} = require('http-proxy-middleware');
const { jwt, db, JWT_SECRET, GATEWAY_SECRET, logAudit } = require('./common');
const { decide } = require('./policy');

const app = express();
app.use(express.json());
const ACCESS_MIN = Number(process.env.ACCESS_TOKEN_MINUTES || 10);
const REFRESH_DAYS = Number(process.env.REFRESH_TOKEN_DAYS || 1);
const SERVICE_MIN = Number(process.env.SERVICE_TOKEN_MINUTES || 5);
const CLIENT_ID = process.env.SERVICE_CLIENT_ID || 'nilai-service';
const CLIENT_SECRET = process.env.SERVICE_CLIENT_SECRET || 'service-secret-demo';

app.get('/', (_req,res) => res.json({service:'Zero Trust API Gateway', status:'running', port:3000}));
app.post('/auth/login', (req,res) => {
 const { username, password } = req.body || {};
 const deviceId = req.headers['x-device-id'];
 const user = db.prepare('SELECT * FROM users WHERE username=?').get(username || '');
 if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
   logAudit(username || 'anonymous','/auth/login',deviceId,'deny','Kredensial salah');
   return res.status(401).json({error:'Login gagal',reason:'Username atau password salah'});
 }
 if (!deviceId || !db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(user.id,deviceId)) {
   logAudit(user.username,'/auth/login',deviceId,'deny','Device tidak terdaftar');
   return res.status(403).json({error:'Login ditolak',reason:'Device tidak terdaftar untuk user ini'});
 }
 const accessToken = jwt.sign({sub:user.username,uid:user.id,role:user.role,tokenType:'user'},JWT_SECRET,{expiresIn:`${ACCESS_MIN}m`});
 const refreshToken = crypto.randomBytes(40).toString('hex');
 const hash = crypto.createHash('sha256').update(refreshToken).digest('hex');
 db.prepare('INSERT INTO refresh_tokens(user_id,token_hash,expires_at,revoked) VALUES(?,?,?,0)')
   .run(user.id,hash,Math.floor(Date.now()/1000)+REFRESH_DAYS*86400);
 logAudit(user.username,'/auth/login',deviceId,'allow','Kredensial dan device valid');
 res.json({accessToken,refreshToken,expiresIn:`${ACCESS_MIN} minutes`,user:{username:user.username,role:user.role,nim:user.nim}});
});
app.post('/auth/refresh',(req,res)=>{
 const token = (req.body||{}).refreshToken;
 if(!token) return res.status(400).json({error:'refreshToken wajib diisi'});
 const hash = crypto.createHash('sha256').update(token).digest('hex');
 const row = db.prepare('SELECT rt.*,u.username,u.role,u.nim FROM refresh_tokens rt JOIN users u ON u.id=rt.user_id WHERE token_hash=?').get(hash);
 if(!row || row.revoked || row.expires_at < Math.floor(Date.now()/1000)) {
  logAudit('unknown','/auth/refresh',req.headers['x-device-id'],'deny','Refresh token tidak valid, kedaluwarsa, atau dicabut');
  return res.status(401).json({error:'Refresh token tidak valid'});
 }
 const accessToken = jwt.sign({sub:row.username,uid:row.user_id,role:row.role,tokenType:'user'},JWT_SECRET,{expiresIn:`${ACCESS_MIN}m`});
 res.json({accessToken,expiresIn:`${ACCESS_MIN} minutes`});
});
app.post('/auth/logout',(req,res)=>{
 const token = (req.body||{}).refreshToken;
 if(!token) return res.status(400).json({error:'refreshToken wajib diisi'});
 const hash = crypto.createHash('sha256').update(token).digest('hex');
 const result = db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE token_hash=? AND revoked=0').run(hash);
 logAudit('user','/auth/logout',req.headers['x-device-id'],result.changes?'allow':'deny',result.changes?'Refresh token dicabut':'Refresh token tidak ditemukan atau sudah dicabut');
 res.json({message:result.changes?'Logout berhasil; refresh token dicabut':'Token tidak ditemukan atau sudah dicabut'});
});
app.post('/auth/service',(req,res)=>{
 const {clientId,clientSecret} = req.body || {};
 if(clientId!==CLIENT_ID || clientSecret!==CLIENT_SECRET) {
  logAudit(clientId||'unknown','/auth/service','service','deny','Client ID/secret salah');
  return res.status(401).json({error:'Autentikasi service gagal'});
 }
 const token = jwt.sign({sub:clientId,role:'service',tokenType:'service'},JWT_SECRET,{expiresIn:`${SERVICE_MIN}m`});
 logAudit(clientId,'/auth/service','service','allow','Service credential valid');
 res.json({accessToken:token,expiresIn:`${SERVICE_MIN} minutes`});
});

function gatewayGuard(req,res,next) {
 const auth = req.headers.authorization || '';
 if(!auth.startsWith('Bearer ')) {
  logAudit('anonymous',req.path,req.headers['x-device-id'],'deny','Access token tidak ada');
  return res.status(401).json({error:'Access token wajib ada'});
 }
 let payload;
 try { payload = jwt.verify(auth.slice(7),JWT_SECRET); }
 catch(e) {
  logAudit('unknown',req.path,req.headers['x-device-id'],'deny','Token tidak valid atau kedaluwarsa');
  return res.status(401).json({error:'Token tidak valid atau kedaluwarsa'});
 }
 const policyPath = (req.originalUrl || req.path).split('?')[0];
 const decision = decide({user:payload,method:req.method,path:policyPath,deviceId:req.headers['x-device-id']});
 logAudit(payload.sub,policyPath,req.headers['x-device-id'],decision.allow?'allow':'deny',decision.reason);
 if(!decision.allow) return res.status(403).json({error:'Akses ditolak',reason:decision.reason});
 req.gatewayPayload = payload;
 next();
}
const proxyOpts = target => ({
  target,
  changeOrigin: true,
  pathRewrite: path => path,

  on: {
    proxyReq: (proxyReq, req) => {

      // Atur semua header sebelum mengirim body
      proxyReq.setHeader(
        'X-Gateway-Secret',
        GATEWAY_SECRET
      );

      if (req.headers.authorization) {
        proxyReq.setHeader(
          'Authorization',
          req.headers.authorization
        );
      }

      if (req.headers['x-device-id']) {
        proxyReq.setHeader(
          'X-Device-ID',
          req.headers['x-device-id']
        );
      }

      // Teruskan body JSON yang sudah dibaca Express
      fixRequestBody(proxyReq, req);
    }
  }
});
const nilaiProxy = createProxyMiddleware(proxyOpts('http://127.0.0.1:3001'));
const transkripProxy = createProxyMiddleware(proxyOpts('http://127.0.0.1:3002'));
app.use(['/nilai','/kelas'], gatewayGuard, (req,res,next) => { req.url = req.originalUrl; nilaiProxy(req,res,next); });
app.use('/transkrip', gatewayGuard, (req,res,next) => { req.url = req.originalUrl; transkripProxy(req,res,next); });
app.get('/audit', (req,res)=>{
 const auth = req.headers.authorization || '';
 try {
  const p = jwt.verify(auth.replace(/^Bearer /,''),JWT_SECRET);
  if(p.role!=='admin') return res.status(403).json({error:'Hanya admin dapat melihat audit log'});
  res.json(db.prepare('SELECT time,subject,endpoint,device,result,reason FROM audit_logs ORDER BY id DESC LIMIT 200').all());
 } catch(e) { res.status(401).json({error:'Token admin tidak valid'}); }
});
const port = Number(process.env.PORT_GATEWAY || 3000);
app.listen(port,()=>console.log(`API Gateway berjalan pada http://localhost:${port}`));
