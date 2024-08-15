### Implementasi Autentikasi dan Otorisasi Berbasis JWT

project ini berfokus pada implementasi sistem autentikasi dan otorisasi yang kuat pada aplikasi Spring Boot 3.0 menggunakan JSON Web Token (JWT). 
Tujuan utama proyek ini adalah untuk mengamankan akses ke API dan resource aplikasi, 
serta memberikan kontrol akses yang granular berdasarkan peran dan izin pengguna.


Fitur Utama:

- Autentikasi JWT: Menggunakan JWT untuk memverifikasi identitas pengguna dan menghasilkan token yang aman.

- Registrasi dan Login: Memungkinkan pengguna untuk mendaftar akun baru dan masuk ke sistem menggunakan kredensial yang valid.

- Refresh Token: Menerapkan mekanisme refresh token untuk memperpanjang masa berlaku token akses tanpa harus meminta pengguna untuk login ulang secara berkala.

- Otorisasi Berbasis Peran dan Izin: Mengimplementasikan sistem otorisasi yang memungkinkan untuk mengontrol akses ke resource berdasarkan peran dan izin pengguna.
- Logout: Memungkinkan pengguna untuk keluar dari sistem dengan cara yang aman, membatalkan token yang aktif.
- Keamanan: Menggunakan praktik keamanan terbaik untuk melindungi aplikasi dari serangan seperti CSRF, XSS, dan injection.


Alur Kerja:

- Registrasi: Pengguna mendaftar akun baru dengan memberikan informasi yang diperlukan.
- Autentikasi: Pengguna melakukan login dengan memasukkan kredensial yang valid. Server akan memverifikasi kredensial dan menghasilkan token JWT.
- Akses ke Resource: Klien mengirimkan permintaan ke server dengan menyertakan token JWT di header permintaan. Server memvalidasi token dan jika valid, akan mengizinkan akses ke resource yang sesuai dengan peran dan izin pengguna.
- Refresh Token: Jika token akses kedaluwarsa, klien dapat menggunakan refresh token untuk mendapatkan token akses baru tanpa harus melakukan login ulang.
- Logout: Pengguna dapat keluar dari sistem dengan mengirimkan permintaan logout. Server akan membatalkan token yang aktif.
