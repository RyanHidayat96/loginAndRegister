# Laporan Pemeriksaan dan Pengujian

Tanggal pengujian: 19 Oktober 2026 (WIB)  
Status: **LULUS — 21 test, 0 gagal, 0 error, 0 dilewati**

## Ruang lingkup

Pemeriksaan mencakup kecocokan terhadap kebutuhan registrasi dan login berbasis email/password, struktur Spring Boot, validasi, penanganan error, serta kontrol keamanan yang relevan. Konfigurasi Java menggunakan **Java 21**, sesuai arahan terbaru dan runtime lokal (`Java 21.0.8`).

## Perintah dan hasil

```text
mvn test

Tests run: 21, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Rincian hasil:

| Suite | Jumlah | Hasil |
| --- | ---: | --- |
| `AuthControllerTest` | 15 | Lulus |
| `PasswordSecurityTest` | 1 | Lulus |
| `InMemoryUserRepositoryTest` | 5 | Lulus |

## Kesesuaian kebutuhan

| Kebutuhan | Bukti | Status |
| --- | --- | --- |
| Java 21 dan Spring Boot | `pom.xml` menetapkan `java.version` ke `21`; aplikasi menggunakan Spring Boot 3.3.4. | Lulus |
| Struktur aplikasi | Controller, service, repository, DTO, konfigurasi, dan exception handler dipisahkan menurut tanggung jawab. | Lulus |
| `POST /register` form-urlencoded | Register berhasil mengembalikan `User registered successfully.` | Lulus |
| `POST /login` form-urlencoded | Login dengan kredensial benar mengembalikan `Login successful`. | Lulus |
| Penyimpanan in-memory | `ConcurrentHashMap` dengan normalisasi email; data hilang saat aplikasi restart sesuai kebutuhan in-memory. | Lulus |
| Password aman | BCrypt strength 12, salt per hash, password plaintext tidak disimpan pada objek pengguna. | Lulus |
| Validasi | Email wajib dan valid, maksimum 254 karakter; password wajib, minimum 8 karakter, maksimum 72 byte UTF-8. | Lulus |
| Error dasar | Email duplikat `409`, kredensial salah/tidak ada `401` dengan pesan sama, input atau JSON rusak `400`. | Lulus |

Format JSON juga didukung sebagai tambahan, tanpa mengubah dukungan `application/x-www-form-urlencoded` yang diminta.

## Pemetaan kriteria evaluasi

| Kriteria | Penilaian berbasis bukti |
| --- | --- |
| Code Structure (30%) | Memenuhi: pemisahan controller, service, repository, DTO, konfigurasi, dan handler error jelas. |
| Functionality & Problem Solving (30%) | Memenuhi: alur register/login, BCrypt, duplikasi, normalisasi email, race condition, dan lockout diuji. |
| AI Prompting & Usage (30%) | Tidak dapat dinilai dari source repository saja. Dalam pekerjaan ini, perubahan dibuat setelah temuan diuji: race condition pendaftaran, batas BCrypt 72 byte, CORS wildcard, dan JSON rusak. |
| Validation & Error Handling (10%) | Memenuhi: validasi field dan respons `400`/`401`/`409`/`429` terstruktur diuji. |

## Perbaikan keamanan yang diterapkan

1. Pendaftaran kini memakai `ConcurrentHashMap.putIfAbsent` melalui `saveIfAbsent`. Ini menutup race condition ketika dua request mendaftarkan email yang sama secara bersamaan.
2. Password dibatasi hingga 72 byte UTF-8. BCrypt mengabaikan byte setelah batas ini; pembatasan mencegah dua password berbeda diperlakukan sama.
3. Validasi password yang sama diterapkan saat login untuk mencegah payload terlalu besar mencapai BCrypt.
4. Throttling lima kegagalan login dibatasi pada kombinasi email dan alamat klien langsung. Klien yang menyerang tidak dapat mengunci pengguna sah dari alamat lain. Respons lockout adalah `429` dan menyertakan `Retry-After`.
5. CORS wildcard dihapus. Akses lintas-origin ditolak secara default sampai origin UI tepercaya didaftarkan secara eksplisit.
6. Ditambahkan `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `Referrer-Policy: no-referrer`, dan cache response sensitif tidak disimpan.
7. JSON yang tidak dapat diparse sekarang menghasilkan `400 Bad Request` tanpa detail parser internal.

## Skenario keamanan yang diuji

- Hash BCrypt bukan plaintext dan hanya password benar yang cocok.
- Login form dan JSON berhasil dengan kredensial yang benar.
- Login email dengan kapitalisasi berbeda berhasil setelah normalisasi.
- Email duplikat ditolak.
- Email invalid, password pendek, password lebih dari 72 byte, dan JSON rusak ditolak.
- Password salah dan email tidak terdaftar sama-sama menghasilkan `401 Invalid email or password.`
- Lockout aktif setelah lima kegagalan; `Retry-After` ada pada respons `429`.
- Lockout dari satu alamat klien tidak memblokir login benar dari alamat klien lain.
- Header keamanan terkirim dan respons tidak memberikan `Access-Control-Allow-Origin` ke origin tak tepercaya.
- Penyimpanan atomik mempertahankan pengguna pertama untuk email yang sama.

## Batasan dan tindak lanjut produksi

- Login saat ini memvalidasi kredensial dan mengembalikan teks sukses, persis seperti kontrak yang diminta. Belum ada token, cookie sesi, atau endpoint terproteksi. Website produksi memerlukan mekanisme autentikasi lanjutan, misalnya sesi `HttpOnly; Secure; SameSite` atau token yang dikelola dengan rotasi dan masa berlaku.
- User dan data throttle berada di memori; keduanya hilang setelah restart dan tidak cocok untuk banyak instance. Gunakan database untuk user dan penyimpanan bersama seperti Redis untuk rate limit pada deployment produksi.
- Pastikan TLS/HTTPS dipaksakan di reverse proxy atau server produksi. HSTS baru efektif pada koneksi HTTPS.
- Jika aplikasi ditempatkan di balik reverse proxy, alamat klien harus diteruskan hanya oleh proxy tepercaya; jangan memercayai header `X-Forwarded-For` dari internet secara langsung.
- Jangan mengaktifkan logging DEBUG Spring MVC di produksi. Framework dapat memasukkan nilai input yang ditolak ke log debug. Konfigurasi aplikasi menetapkan log produksi pada INFO.
- Pengujian HTTP dilakukan melalui `MockMvc` dengan Spring Security filter chain aktif. Menjalankan `mvn spring-boot:run` tidak dapat diverifikasi di sandbox ini karena Maven tidak diizinkan menulis artefak plugin yang belum ada ke `C:\Users\exery\.m2`; kegagalan tersebut bukan kegagalan kode aplikasi.
- Pemindaian CVE dependency tidak dijalankan dalam pemeriksaan ini. Jalankan SCA terautentikasi di CI sebelum rilis publik.

## Status publikasi repository

Direktori kerja ini belum merupakan repository Git dan tidak memiliki remote tujuan. Koneksi GitHub telah diminta agar publikasi dapat dilakukan, tetapi belum terhubung pada sesi ini. Setelah koneksi disetujui, berikan URL repository publik tujuan atau pilih repository dari akun GitHub untuk melanjutkan push.
