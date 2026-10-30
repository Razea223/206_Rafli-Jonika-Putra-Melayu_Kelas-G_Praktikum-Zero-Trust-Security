const express = require('express');
const { db, jwt, JWT_SECRET, verifyServiceRequest } = require('./common');
const app = express(); app.use(express.json());
app.get('/health',(_req,res)=>res.json({service:'nilai',status:'running'}));
app.use(verifyServiceRequest);
app.get('/nilai',(req,res)=>{
 const p=req.auth;
 let rows;
 if(p.tokenType==='service') return res.status(403).json({error:'Token service tidak untuk melihat nilai'});
 if(p.role==='mahasiswa') {
  const u=db.prepare('SELECT nim FROM users WHERE id=?').get(p.uid);
  rows=db.prepare('SELECT g.id,c.nama AS kelas,g.nim,g.nilai,g.final FROM grades g JOIN classes c ON c.id=g.class_id WHERE g.nim=?').all(u.nim);
 } else if(p.role==='dosen') {
  rows=db.prepare('SELECT g.id,c.nama AS kelas,g.nim,g.nilai,g.final FROM grades g JOIN classes c ON c.id=g.class_id WHERE c.dosen_id=?').all(p.uid);
 } else return res.status(403).json({error:'Role tidak diizinkan'});
 res.json(rows);
});
app.put('/nilai/:id',(req,res)=>{
 const {nilai}=req.body||{};
 if(!Number.isFinite(Number(nilai)) || Number(nilai)<0 || Number(nilai)>100) return res.status(400).json({error:'Nilai harus angka 0-100'});
 const g=db.prepare('SELECT * FROM grades WHERE id=?').get(Number(req.params.id));
 if(!g) return res.status(404).json({error:'Data nilai tidak ditemukan'});
 if(g.final) return res.status(409).json({error:'Nilai sudah final'});
 db.prepare('UPDATE grades SET nilai=? WHERE id=?').run(Number(nilai),g.id);
 res.json({message:'Nilai berhasil diperbarui',id:g.id,nilai:Number(nilai)});
});
app.post('/kelas/:id/finalisasi',async(req,res)=>{
 const classId=Number(req.params.id);
 const cls=db.prepare('SELECT * FROM classes WHERE id=?').get(classId);
 if(!cls) return res.status(404).json({error:'Kelas tidak ditemukan'});
 const rows=db.prepare('SELECT * FROM grades WHERE class_id=?').all(classId);
 db.prepare('UPDATE grades SET final=1 WHERE class_id=?').run(classId);
 try {
  const r=await fetch('http://127.0.0.1:3000/auth/service',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({clientId:process.env.SERVICE_CLIENT_ID||'nilai-service',clientSecret:process.env.SERVICE_CLIENT_SECRET||'service-secret-demo'})});
  if(!r.ok) throw new Error('Gagal memperoleh token service dari gateway');
  const {accessToken}=await r.json();
  const sync=await fetch('http://127.0.0.1:3000/transkrip/sinkron',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${accessToken}`,'X-Device-ID':'service-nilai'},body:JSON.stringify({classId,grades:rows.map(x=>({nim:x.nim,nilai:x.nilai}))})});
  const body=await sync.json();
  if(!sync.ok) throw new Error(body.reason||body.error||'Sinkronisasi gagal');
  res.json({message:'Kelas difinalisasi dan transkrip disinkronkan',classId,synced:rows.length});
 } catch(e) {
  res.status(502).json({error:'Nilai difinalisasi, tetapi sinkronisasi transkrip gagal',reason:e.message});
 }
});
const port=Number(process.env.PORT_NILAI||3001);
app.listen(port,()=>console.log(`Service Nilai berjalan pada port ${port}`));
