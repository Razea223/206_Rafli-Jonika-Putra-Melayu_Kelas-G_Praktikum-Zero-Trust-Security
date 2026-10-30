const express = require('express');
const { db, verifyServiceRequest } = require('./common');
const app=express(); app.use(express.json());
app.get('/health',(_req,res)=>res.json({service:'transkrip',status:'running'}));
app.use(verifyServiceRequest);
app.get('/transkrip/:nim',(req,res)=>{
 const p=req.auth;
 if(p.tokenType==='service') return res.status(403).json({error:'Token service tidak untuk membaca transkrip'});
 const rows=db.prepare('SELECT t.nim,c.nama AS kelas,t.nilai,t.updated_at FROM transcripts t JOIN classes c ON c.id=t.class_id WHERE t.nim=?').all(req.params.nim);
 res.json(rows);
});
app.post('/transkrip/sinkron',(req,res)=>{
 if(req.auth.tokenType!=='service'||req.auth.role!=='service') return res.status(403).json({error:'Hanya token service yang diizinkan'});
 const {classId,grades}=req.body||{};
 if(!Number.isInteger(Number(classId))||!Array.isArray(grades)) return res.status(400).json({error:'classId dan grades wajib valid'});
 const cls=db.prepare('SELECT id FROM classes WHERE id=?').get(Number(classId));
 if(!cls) return res.status(404).json({error:'Kelas tidak ditemukan'});
 const upsert=db.prepare(`INSERT INTO transcripts(nim,class_id,nilai,updated_at) VALUES(?,?,?,?)
 ON CONFLICT(nim,class_id) DO UPDATE SET nilai=excluded.nilai,updated_at=excluded.updated_at`);
 const tx=db.transaction(()=>{ for(const g of grades) upsert.run(String(g.nim),Number(classId),Number(g.nilai),new Date().toISOString()); });
 tx();
 res.json({message:'Transkrip berhasil disinkronkan',count:grades.length});
});
const port=Number(process.env.PORT_TRANSKRIP||3002);
app.listen(port,()=>console.log(`Service Transkrip berjalan pada port ${port}`));
