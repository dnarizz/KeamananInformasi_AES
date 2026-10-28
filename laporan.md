# Tugas 2 Keamanan Informasi: Implementasi Manual AES-128 & Key Distribution Scenario (KDC)

Repositori ini berisi implementasi dari nol (*from scratch*) algoritma kriptografi simetris **AES-128 (Advanced Encryption Standard)** dan protokol distribusi kunci **Needham-Schroeder (Key Distribution Scenario)**[cite: 1] menggunakan bahasa pemrograman Python dan komunikasi jaringan **TCP Socket** lintas perangkat (3 IP berbeda).

---

## 👥 Anggota Kelompok
| Nama Lengkap | NRP | Peran & Kontribusi |
| :--- | :--- | :--- |
| **Danar Rizkia Yuda** | **5025241128** | Implementasi algoritma AES-128 manual (`aes.py`), Integrasi Alice & KDC, Pengujian Wireshark |
| **Muhammad Cholaif Al Ghifari** | **5025241210** | Implementasi Server KDC (`kdc.py`), Komunikasi Dua Arah Peer Node (`node.py`), Dokumentasi |

---

## 📂 Struktur File Repositori
Proyek ini dirancang dengan arsitektur modular 3 file utama tanpa ketergantungan pada *library* kriptografi eksternal:

```text
📦 Tugas2-KI
 ┣ 📜 aes.py       # Mesin algoritma AES-128 manual (Key Expansion, Encrypt, Decrypt, PKCS#7)
 ┣ 📜 kdc.py       # Server Key Distribution Center (KDC) untuk Langkah 1 & 2
 ┣ 📜 node.py      # Program entitas untuk Alice (Initiator) & Bob (Responder) + Full-Duplex Chat
 ┗ 📜 README.md    # Dokumentasi arsitektur, alur protokol, dan panduan penggunaan
```

---

## 🔐 1. Penjelasan Implementasi AES-128 Manual (`aes.py`)
Seluruh proses enkripsi dan dekripsi diimplementasikan secara manual mengikuti spesifikasi standar FIPS 197 (AES-128: panjang blok 128-bit / 16 byte, panjang kunci 128-bit / 16 byte, dan 10 ronde):

1. **Format Input & Output:**
   * **Key & Plaintext:** Diterima dalam format **ASCII** dan dikonversi ke *byte array*. Kunci dinormalisasi menjadi tepat 16 byte (`normalize_key`).
   * **Padding:** Menggunakan standar **PKCS#7 Padding** (`pkcs7_pad` dan `pkcs7_unpad`) agar *plaintext* dengan panjang karakter berapa pun selalu menjadi kelipatan blok 16 byte, sekaligus berfungsi mendeteksi ketidakcocokan kunci saat dekripsi.
   * **Ciphertext:** Hasil akhir enkripsi dikonversi dan ditransmisikan melalui jaringan dalam format **Hexadecimal (Hex)**.
2. **Key Expansion (`key_expansion`):**
   * Mengekspansi kunci utama 16 byte (4 *words*) menjadi 44 *words* (11 *Round Keys* untuk ronde ke-0 hingga ronde ke-10) menggunakan operasi rotasi *byte* (`RotWord`), substitusi dengan `S_BOX` (`SubWord`), dan XOR terhadap konstanta `RCON`.
3. **Proses Enkripsi per Blok 16 Byte (`encrypt_block`):**
   * **Initial Round:** Operasi `add_round_key` menggunakan *Round Key* ke-0.
   * **Main Rounds (Ronde 1 s.d. 9):** Menjalankan 4 transformasi berurutan:
     1. `sub_bytes`: Substitusi non-linear setiap byte pada matriks *State* $4 \times 4$ menggunakan tabel `S_BOX`.
     2. `shift_rows`: Pergeseran baris matriks *State* secara siklik ke kiri (baris ke-$r$ digeser sejauh $r$ byte).
     3. `mix_columns`: Perkalian matriks kolom pada *Galois Field* $GF(2^8)$ menggunakan fungsi `gmul` dengan polinomial ireduksibel $x^8 + x^4 + x^3 + x + 1$ (`0x1B`).
     4. `add_round_key`: Operasi XOR antara matriks *State* dan *Round Key* ronde berjalan.
   * **Final Round (Ronde 10):** Menjalankan `sub_bytes`, `shift_rows`, dan `add_round_key` (tanpa `mix_columns`).
4. **Proses Dekripsi per Blok 16 Byte (`decrypt_block`):**
   * Kebalikan dari proses enkripsi menggunakan *Round Keys* secara mundur (ronde 10 ke ronde 0) melalui tahapan `inv_shift_rows`, `inv_sub_bytes` (dengan tabel `INV_S_BOX`), `add_round_key`, dan `inv_mix_columns`.

---

## 🔄 2. Arsitektur & Alur Protokol Key Distribution (5 Langkah)

Skenario melibatkan 3 entitas pada 3 alamat IP berbeda: **KDC**[cite: 1], **Alice (Initiator A)**[cite: 1], dan **Bob (Responder B)**[cite: 1]. Pra-kondisi awal adalah Alice berbagi *Master Key* $K_a$ dengan KDC[cite: 1], dan Bob berbagi *Master Key* $K_b$ dengan KDC[cite: 1].

```text
                     +-----------------------------------+
                     |   Key Distribution Center (KDC)   |
                     |          (IP Entitas 1)           |
                     +-----------------------------------+
                        ^                             |
       (1) IDA||IDB||N1 |                             | (2) E(Ka, [Ks||IDA||IDB||N1])
                        |                             |     || E(Kb, [Ks||IDA])
                        |                             v
            +-----------------------+     +-----------------------+
            |  Alice (Initiator A)  |     |   Bob (Responder B)   |
            |    (IP Entitas 2)     |     |    (IP Entitas 3)     |
            +-----------------------+     +-----------------------+
                        |                             ^
                        | (3) E(Kb, [Ks||IDA])        |
                        +---------------------------->|
                        |                             |
                        | (4) E(Ks, N2)               |
                        |<----------------------------+
                        |                             |
                        | (5) E(Ks, f(N2))            |
                        +---------------------------->|
                        |                             |
                        |<==== Komunikasi 2 Arah ====>|
                        |    Full-Duplex AES (Ks)     |
```

### Rincian Teknis Tiap Langkah:
1. **Langkah 1 — Permintaan Kunci Sesi (`Alice -> KDC`):**
   * Alice membangkitkan *Nonce* acak $N_1$ dan mengirimkan string *plaintext* ASCII: `ID_A||ID_B||N1` ke KDC[cite: 1].
2. **Langkah 2 — Penerbitan Session Key & Tiket (`KDC -> Alice`):**
   * KDC membangkitkan **Session Key ($K_s$)** baru[cite: 1].
   * KDC mengenkripsi blok untuk Alice menggunakan $K_a$: $E(K_a, [K_s \parallel ID_A \parallel ID_B \parallel N_1])$ dalam format Hex[cite: 1].
   * KDC mengenkripsi tiket untuk Bob menggunakan $K_b$: $E(K_b, [K_s \parallel ID_A])$ dalam format Hex[cite: 1].
   * KDC mengirim kedua ciphertext Hex tersebut (`Hex_Alice||Hex_Tiket_Bob`) ke Alice[cite: 1]. Alice mendekripsi bagian pertama dengan $K_a$, memverifikasi kecocokan $N_1$ dan $ID_B$, lalu menyimpan $K_s$[cite: 1].
3. **Langkah 3 — Pengiriman Tiket (`Alice -> Bob`):**
   * Alice meneruskan tiket terenkripsi $E(K_b, [K_s \parallel ID_A])$ (Hex) ke Bob[cite: 1].
   * Bob mendekripsi tiket tersebut menggunakan $K_b$ miliknya dan memperoleh $K_s$ serta identitas pengirim ($ID_A$)[cite: 1].
4. **Langkah 4 — Tantangan Autentikasi / *Challenge* (`Bob -> Alice`):**
   * Untuk mencegah *Replay Attack*, Bob membangkitkan *Nonce* baru $N_2$, mengenkripsinya dengan kunci sesi $K_s$ menjadi $E(K_s, N_2)$ (Hex), dan mengirimkannya ke Alice[cite: 1].
5. **Langkah 5 — Respons Autentikasi (`Alice -> Bob`):**
   * Alice mendekripsi tantangan Bob menggunakan $K_s$ untuk mendapatkan nilai $N_2$, menghitung fungsi $f(N_2) = N_2 - 1$, mengenkripsinya kembali dengan $K_s$ menjadi $E(K_s, f(N_2))$ (Hex), lalu mengirimkannya ke Bob[cite: 1].
   * Bob mendekripsi balasan tersebut dengan $K_s$ dan memverifikasi bahwa hasilnya sama dengan $N_2 - 1$[cite: 1].
6. **Komunikasi Dua Arah (*Full-Duplex AES Chat*):**
   * Setelah Langkah 5 terverifikasi, koneksi TCP antara Alice dan Bob dipertahankan menggunakan *multithreading* (`chat_receiver_loop` di *background* dan input pengguna di *foreground*). Baik Alice maupun Bob dapat bertindak sebagai *sender* maupun *receiver* secara simultan menggunakan enkripsi AES dengan kunci sesi $K_s$.

---

## 🚀 3. Panduan Menjalankan Program (3 IP Berbeda)

Pastikan ketiga perangkat berada pada jaringan yang saling terhubung dan *firewall* mengizinkan lalu lintas TCP pada port KDC (`5000`) dan port Bob (`6000`).

### Langkah A: Jalankan Server KDC (Perangkat / IP 1)
```bash
python kdc.py
```
Masukkan konfigurasi awal saat diminta:
* **IP Bind:** Tekan `Enter` (`0.0.0.0`)
* **Port KDC:** Tekan `Enter` (`5000`)
* **Master Key Alice ($K_a$):** Contoh `kunciAlice123456`
* **Master Key Bob ($K_b$):** Contoh `kunciBob12345678`
* **Session Key ($K_s$):** Tekan `Enter` untuk *Auto-Random*, atau ketik kunci ASCII tertentu.

### Langkah B: Jalankan Node Bob / Responder (Perangkat / IP 2)
```bash
python node.py
```
* Pilih Role: `2` (Bob)[cite: 1]
* Masukkan ID Bob (`BOB`), **Master Key Bob ($K_b$)** (`kunciBob12345678`), dan Port Listen (`6000`).

### Langkah C: Jalankan Node Alice / Initiator (Perangkat / IP 3)
```bash
python node.py
```
* Pilih Role: `1` (Alice)[cite: 1]
* Masukkan ID Alice (`ALICE`), ID Tujuan (`BOB`), dan **Master Key Alice ($K_a$)** (`kunciAlice123456`).
* Masukkan **IP KDC** (IP Perangkat 1) dan **IP Bob** (IP Perangkat 2).
* Program akan otomatis mengeksekusi **Langkah 1 s.d. Langkah 5**[cite: 1] dan membuka sesi *chat* dua arah.

---

## 🛠️ 4. Daftar Perintah Interaktif (Tanpa Restart Program)

Untuk memudahkan pengujian berbagai *test case* saat demo, seluruh entitas dilengkapi *Command Line Interface (CLI)* interaktif:

### Pada Terminal KDC (`kdc.py`):
| Perintah | Fungsi |
| :--- | :--- |
| `/info` | Menampilkan status $K_a$, $K_b$, dan mode $K_s$ yang sedang aktif |
| `/setka <key_ascii>` | Mengubah *Master Key* Alice ($K_a$) secara langsung |
| `/setkb <key_ascii>` | Mengubah *Master Key* Bob ($K_b$) secara langsung |
| `/setks <key_ascii>` | Mengatur *Session Key* ($K_s$) secara manual (ketik `/setks auto` untuk kembali ke mode acak) |
| `/exit` | Menghentikan server KDC |

### Pada Terminal Alice & Bob (`node.py`):
| Perintah | Fungsi |
| :--- | :--- |
| `<ketik teks biasa>` | Mengenkripsi pesan (ASCII) dengan $K_s$ dan mengirimkan *Ciphertext* (Hex) ke lawan bicara |
| `/info` | Menampilkan status Role, ID, *Master Key* ($K_a$/$K_b$), *Session Key* ($K_s$), dan status autentikasi |
| `/setmaster <key>` | Mengubah *Master Key* ($K_a$ atau $K_b$) secara langsung tanpa *restart* |
| `/setks <key>` | Mengubah *Session Key* ($K_s$) secara langsung untuk menguji skenario kunci cocok/tidak cocok |
| `/handshake` | *(Khusus Alice)* Mengulangi protokol Langkah 1 s.d. 5 ke KDC dan Bob untuk meminta kunci sesi baru |
| `/enc <plaintext>` | Menguji enkripsi AES mandiri menggunakan $K_s$ aktif (ASCII $\rightarrow$ Hex) |
| `/dec <cipher_hex>` | Menguji dekripsi AES mandiri menggunakan $K_s$ aktif (Hex $\rightarrow$ ASCII) |
| `/exit` | Memutus koneksi dan keluar dari program |

---

## 🦈 5. Panduan Observasi Paket di Wireshark

1. Buka **Wireshark** dan pilih *network interface* yang aktif (misal: `Wi-Fi` dan/atau `VMware Network Adapter VMnet`).
2. Gunakan filter tampilan berikut untuk mengamati murni paket protokol KDC (Port `5000`) dan komunikasi Alice-Bob (Port `6000`):
   ```text
   (tcp.port == 5000 || tcp.port == 6000) && tcp.len > 0
   ```
3. **Verifikasi Payload Paket:**
   * **Paket 1 (`Alice -> KDC`, Port 5000):** Terlihat *plaintext* ASCII `ALICE||BOB||<N1>`[cite: 1].
   * **Paket 2 (`KDC -> Alice`, Port 5000):** Terlihat dua blok *Ciphertext* Hex yang dipisahkan delimiter `||`[cite: 1].
   * **Paket 3 (`Alice -> Bob`, Port 6000):** Terlihat *Ciphertext* Hex tiket Bob[cite: 1].
   * **Paket 4 & 5 (`Bob <-> Alice`, Port 6000):** Terlihat *Ciphertext* Hex dari $E(K_s, N_2)$ dan $E(K_s, f(N_2))$[cite: 1].
   * **Paket Selanjutnya (Port 6000):** Transmisi pesan dua arah terenkripsi AES dalam format Hexadecimal.
