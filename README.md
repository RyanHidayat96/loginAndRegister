# Secure User Authentication System (Java 21 & Spring Boot)

Sistem autentikasi pengguna (Registrasi & Login) berbasis **Java 21 (LTS)** dan **Spring Boot 3** dengan standar keamanan tinggi (*enterprise-grade security*).

---

## 🛡️ Aspek Keamanan Tingkat Tinggi (High Security Measures)

1. **Enkripsi Password dengan BCrypt (Strength 12)**:
   - Password di-hash menggunakan algoritma `BCryptPasswordEncoder` dengan faktor kerja (*work factor*) 12 dan *cryptographic salt* unik untuk setiap pengguna.
   - Password *plaintext* **tidak pernah** disimpan di memori maupun dicatat ke dalam log (masking `[PROTECTED]` pada `toString()`).

2. **Mitigasi Serangan Timing (*Timing-Attack Mitigation*)**:
   - Jika pengguna memasukkan email yang tidak terdaftar saat login, sistem secara otomatis mengeksekusi komputasi hash tiruan (*dummy hash verification*).
   - Hal ini membuat waktu respons verifikasi konstan, mencegah penyerang melakukan *User Enumeration* berdasarkan perbedaan waktu respons server.

3. **Proteksi Serangan Brute-Force & Rate Limiting (*Account Lockout*)**:
   - Sistem membatasi percobaan login yang gagal berturut-turut (maksimal 5 kali percobaan gagal).
   - Setelah 5 kali kegagalan, akun akan dikunci sementara selama 15 menit dan mengembalikan HTTP status `429 Too Many Requests` disertai header `Retry-After`.

4. **Normalisasi Email & Thread-Safe In-Memory Storage**:
   - Penyimpanan berbasis `ConcurrentHashMap` yang aman untuk multi-threading (*thread-safe*).
   - Email dinormalisasi (*trim* dan *lowercase*) sebelum disimpan atau dicari untuk mencegah duplikasi akun atau bypass otentikasi akibat perbedaan huruf besar/kecil (*case-sensitivity attack*).

5. **Validasi Input Ketat (Jakarta Bean Validation)**:
   - Email divalidasi dengan format RFC standar dan batas panjang (maks. 254 karakter).
   - Password divalidasi dengan panjang minimum 8 karakter dan batas wajar maksimum 128 karakter untuk mencegah serangan *Denial of Service (DoS)* via payload raksasa.

6. **Pencegahan Kebocoran Informasi (*Information Disclosure / CWE-209*)**:
   - Pesan kesalahan login diseragamkan menjadi `"Invalid email or password."` baik untuk kasus user tidak ditemukan maupun password salah.
   - `GlobalExceptionHandler` menangani eksepsi secara terpusat tanpa mengekspos *stack trace* atau *internal error* ke klien.

7. **Konfigurasi HTTP Security Headers**:
   - `X-Frame-Options: DENY` (mencegah Clickjacking).
   - `X-Content-Type-Options: nosniff` (mencegah MIME confusion attacks).
   - `SessionCreationPolicy.STATELESS` (meniadakan risiko session fixation / session hijacking).

---

## 🏛️ Struktur Proyek (Clean Architecture)

```
src/main/java/com/security/auth/
├── LoginAndRegisterApplication.java    # Spring Boot Main Class
├── config/
│   ├── PasswordEncoderConfig.java      # BCrypt Configuration (Strength 12)
│   └── SecurityConfig.java             # Security Filter Chain & Headers
├── controller/
│   └── AuthController.java             # Endpoint POST /register & /login
├── dto/
│   ├── ErrorResponse.java              # Standarisasi JSON error response
│   ├── LoginRequest.java               # DTO validasi login (Form & JSON)
│   └── RegisterRequest.java            # DTO validasi registrasi (Form & JSON)
├── exception/
│   ├── AccountLockedException.java     # Exception saat akun terkunci
│   ├── GlobalExceptionHandler.java     # Centralized exception handling
│   ├── InvalidCredentialsException.java# Exception saat kredensial salah
│   └── UserAlreadyExistsException.java # Exception saat email duplikat
├── model/
│   └── User.java                       # Domain User Entity
├── repository/
│   ├── InMemoryUserRepository.java     # Implementasi ConcurrentHashMap
│   └── UserRepository.java             # Repository Interface
└── service/
    ├── AuthService.java                # Interface kontrak registrasi & login
    ├── AuthServiceImpl.java            # Implementasi logika bisnis & security
    └── LoginAttemptService.java        # Layanan proteksi brute force
```

---

## 🚀 Panduan Penggunaan API

Sistem mendukung format `application/x-www-form-urlencoded` sesuai spesifikasi, serta mendukung `application/json`.

### 1. Registrasi Akun

- **URL**: `/register`
- **Method**: `POST`
- **Content-Type**: `application/x-www-form-urlencoded`

**Contoh Request cURL (Form Urlencoded):**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@example.com" \
  -d "password=mypassword123"
```

**Contoh Request cURL (JSON):**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "mypassword123"}'
```

**Response (HTTP 200 OK):**
```
User registered successfully.
```

---

### 2. Login

- **URL**: `/login`
- **Method**: `POST`
- **Content-Type**: `application/x-www-form-urlencoded`

**Contoh Request cURL (Form Urlencoded):**
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@example.com" \
  -d "password=mypassword123"
```

**Contoh Request cURL (JSON):**
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "mypassword123"}'
```

**Response (HTTP 200 OK):**
```
Login successful
```

---

## 🧪 Menjalankan Pengujian (Testing)

Proyek dilengkapi dengan 16 unit dan *integration tests* komprehensif yang memvalidasi seluruh alur positif dan skenario keamanan (*edge cases*).

Jalankan perintah berikut di terminal:

```bash
mvn test
```

### Menjalankan Aplikasi:

```bash
mvn spring-boot:run
```
Aplikasi akan berjalan pada port default: `http://localhost:8080`.
