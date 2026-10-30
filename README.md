# Praktikum Zero Trust Security — Sistem Nilai

Proyek ini mengimplementasikan Zero Trust di tingkat aplikasi: *never trust, always verify*, *least privilege*, dan asumsi bahwa kompromi mungkin terjadi. Semua endpoint pengguna diakses melalui API Gateway (port 3000). Service Nilai (3001) dan Service Transkrip (3002) memerlukan `X-Gateway-Secret` serta token JWT yang valid, sehingga token atau gateway secret saja tidak cukup.

## Kebutuhan
- Node.js 18 atau lebih baru (karena menggunakan `fetch`)
- npm
- Postman atau curl (opsional, untuk pengujian)

## Menjalankan di VS Code
1. Ekstrak ZIP, lalu buka folder `zero_trust_security` di VS Code.
2. Buka Terminal → New Terminal.
3. Jalankan `npm install`.
4. Salin `.env.example` menjadi `.env`. Pada PowerShell jalankan:
   `Copy-Item .env.example .env`
5. Untuk demo lokal, nilai default di source code tetap bisa berjalan tanpa `.env`; untuk penggunaan di luar demo, ganti semua secret dengan nilai acak yang kuat dan jangan bagikan file `.env`.
6. Jalankan ketiga layanan dengan `npm start`. Gateway tersedia di `http://localhost:3000`, Service Nilai di port 3001, dan Service Transkrip di port 3002. Alternatifnya, jalankan `npm run gateway`, `npm run nilai`, dan `npm run transkrip` pada tiga terminal terpisah.
7. Database `zero-trust.db` dibuat otomatis saat program pertama kali dijalankan dan diisi data awal.

## Akun demo dan device ID

| Role | Username | Password | `X-Device-ID` |
|---|---|---|---|
| Admin | `admin` | `Admin123!` | `dev-admin-01` |
| Dosen 1 | `dosen1` | `Dosen123!` | `dev-dosen1-01` |
| Dosen 2 | `dosen2` | `Dosen123!` | `dev-dosen2-01` |
| Mahasiswa 1 | `mhs1` | `Mhs123!` | `dev-mhs1-01` |
| Mahasiswa 2 | `mhs2` | `Mhs123!` | `dev-mhs2-01` |
| Mahasiswa 3 | `mhs3` | `Mhs123!` | `dev-mhs3-01` |

Data awal mencakup 1 admin, 2 dosen, 3 mahasiswa, 2 kelas, dan satu device terdaftar per akun.

## Pengujian dengan PowerShell

### 1. Login mahasiswa
```powershell
$headers = @{ "X-Device-ID" = "dev-mhs1-01" }
$body = @{ username = "mhs1"; password = "Mhs123!" } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri "http://localhost:3000/auth/login" -Headers $headers -ContentType "application/json" -Body $body
$token = $login.accessToken
$auth = @{ Authorization = "Bearer $token"; "X-Device-ID" = "dev-mhs1-01" }
Invoke-RestMethod -Method Get -Uri "http://localhost:3000/nilai" -Headers $auth
```

### 2. Lihat transkrip sendiri
```powershell
Invoke-RestMethod -Method Get -Uri "http://localhost:3000/transkrip/247001" -Headers $auth
```
Mahasiswa hanya boleh melihat NIM miliknya sendiri. Transkrip belum ada sampai kelas terkait difinalisasi dan sinkronisasi berhasil.

### 3. Uji penolakan device tidak terdaftar
Coba login memakai header `X-Device-ID: perangkat-palsu`. Gateway harus menolak permintaan.

### 4. Login dosen, ubah nilai, dan finalisasi kelas
```powershell
$h = @{ "X-Device-ID" = "dev-dosen1-01" }
$b = @{ username = "dosen1"; password = "Dosen123!" } | ConvertTo-Json
$d = Invoke-RestMethod -Method Post -Uri "http://localhost:3000/auth/login" -Headers $h -ContentType "application/json" -Body $b
$dh = @{ Authorization = "Bearer $($d.accessToken)"; "X-Device-ID" = "dev-dosen1-01" }
$update = @{ nilai = 92 } | ConvertTo-Json
Invoke-RestMethod -Method Put -Uri "http://localhost:3000/nilai/1" -Headers $dh -ContentType "application/json" -Body $update
Invoke-RestMethod -Method Post -Uri "http://localhost:3000/kelas/1/finalisasi" -Headers $dh
```
Finalisasi hanya diizinkan untuk kelas yang diampu dosen tersebut dan pada jam 07.00–21.00 waktu lokal server. Setelah final, nilai tidak dapat diubah lagi.

### 5. Lihat audit log sebagai admin
Login sebagai admin dengan device `dev-admin-01`, kemudian panggil `GET http://localhost:3000/audit` dengan header `Authorization: Bearer <token-admin>`. Audit log berisi waktu, subjek, endpoint, device, hasil, dan alasan.

### 6. Uji service tidak bisa diakses langsung
Panggil `http://localhost:3001/nilai` tanpa header `X-Gateway-Secret`; service harus membalas 403. Jika gateway secret ada tetapi token tidak valid/tidak ada, service juga menolak.

## Endpoint
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/service`
- `GET /nilai`
- `PUT /nilai/:id`
- `POST /kelas/:id/finalisasi`
- `GET /transkrip/:nim`
- `POST /transkrip/sinkron` (hanya token service)
- `GET /audit` (admin)

## Catatan penting
- Access token berlaku 10 menit; refresh token 1 hari dan dapat dicabut; token service 5 menit.
- Jam akses dapat diatur melalui `.env` dengan `ACCESS_START_HOUR` dan `ACCESS_END_HOUR`.
- Untuk mengulang demo dari keadaan awal, hentikan server dan hapus file `zero-trust.db`, lalu jalankan kembali. Data akan di-seed ulang.
- Proyek ini adalah implementasi praktikum/demo lokal, bukan konfigurasi produksi. Sebelum produksi, tambahkan rate limiting, HTTPS, validasi skema request, rotasi secret, refresh-token rotation, proteksi CSRF bila memakai cookie, dan pengujian keamanan menyeluruh.
