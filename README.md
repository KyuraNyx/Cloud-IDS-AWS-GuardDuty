# Cloud Based Intrusion Detection System (IDS) AWS

Proyek akhir implementasi arsitektur keamanan awan (cloud native pipeline) dengan pendekatan pertahanan berlapis (Defense in Depth) menggunakan ekosistem Amazon Web Services (AWS) dan utilitas keamanan sumber terbuka.

**Mata Kuliah:** Cloud Computing and Security  
**Institusi:** Fakultas Ilmu Komputer, Universitas Brawijaya (FILKOM UB)  
**Program Studi:** Teknik Komputer  

## Tim Pengembang
1. Hayqal Husein Alhabsyi (245150301111027)
2. Made Nugraha Pradnyana (245150307111012)
3. Faris Arinanta (235150300111045)
4. Syarief Choirul Anwar (245150301111028)

## Deskripsi Proyek
Proyek ini mendemonstrasikan perancangan dan implementasi Intrusion Detection System (IDS) komprehensif yang memadukan dua paradigma deteksi sekaligus untuk melindungi instans peladen dari ancaman siber (seperti pemindaian porta agresif).

1. **Lapis Pertama (Cloud Based IDS):** Memanfaatkan Amazon GuardDuty sebagai mesin kecerdasan tanpa agen yang menganalisis VPC Flow Logs secara terus menerus di latar belakang.
2. **Lapis Kedua (Host Based IDS):** Mengimplementasikan Suricata di dalam sistem operasi Ubuntu untuk melakukan inspeksi paket mendalam (Deep Packet Inspection) secara waktu nyata.

Seluruh peringatan keamanan dikoordinasikan secara otomatis melalui Amazon EventBridge dan dikirimkan ke administrator via Amazon SNS. Log aktivitas kemudian divisualisasikan menggunakan dasbor Grafana yang mengambil data secara langsung dari Amazon CloudWatch.

## Teknologi dan Layanan yang Digunakan
* **Komputasi:** Amazon EC2 (Ubuntu Server)
* **Keamanan Awan:** Amazon GuardDuty
* **Otomatisasi & Notifikasi:** Amazon EventBridge, Amazon SNS
* **Pemantauan & Metrik:** Amazon CloudWatch, CloudWatch Agent
* **Inspeksi Paket Lokal:** Suricata IDS
* **Visualisasi Data:** Grafana

## Struktur Repositori (Infrastructure as Code)
Repositori ini menyimpan rekam jejak konfigurasi infrastruktur dan skrip otomatisasi dengan struktur sebagai berikut:
* `/config` : Berisi berkas parameter JSON untuk pengaturan agen CloudWatch (Unified CloudWatch Agent) guna melakukan pengiriman log (log shipping) ke awan.
* `/rules` : Berisi berkas aturan deteksi kustom Suricata (local.rules) yang telah dioptimalkan (tuning) dengan parameter ambang batas (threshold) untuk mendeteksi paket TCP SYN spesifik.
* `/scripts` : Berisi skrip otomatisasi Bash untuk mempercepat instalasi komponen peladen lokal (Suricata dan Grafana).
* `/docs` : Direktori pendukung untuk menyimpan aset dokumentasi dan tangkapan layar validasi arsitektur.

## Panduan Instalasi dan Penggunaan

### 1. Persiapan Infrastruktur AWS
* Luncurkan instans EC2 (t3.medium) sebagai peladen Target pada wilayah `us-east-1`.
* Pasang IAM Role `LabRole` pada instans tersebut.
* Buka porta 22 (SSH) dan porta 3000 (Grafana) pada Security Group.
* Aktifkan layanan Amazon GuardDuty di konsol AWS.

### 2. Konfigurasi Lapis Host (Suricata & CloudWatch)
Akses peladen Target melalui SSH dan jalankan skrip instalasi, atau lakukan konfigurasi manual berikut:
* Pasang Suricata dan sesuaikan antarmuka jaringan pada berkas `suricata.yaml` menjadi `ens5`.
* Terapkan aturan deteksi kustom dari folder `/rules` ke dalam direktori lokal Suricata.
* Pasang Unified CloudWatch Agent dan muat berkas JSON dari folder `/config` agar agen mulai memantau `/var/log/suricata/fast.log`.

### 3. Konfigurasi Lapis Notifikasi
* Buat topik baru di Amazon SNS dan daftarkan alamat surel administrator (lakukan konfirmasi langganan).
* Buat aturan baru di Amazon EventBridge untuk mencegat aktivitas dengan pola `GuardDuty Finding`.
* Arahkan target aturan EventBridge tersebut ke topik SNS yang telah dibuat.

### 4. Konfigurasi Visualisasi
* Pasang Grafana pada peladen Target.
* Tambahkan sumber data (Data Source) Amazon CloudWatch pada antarmuka Grafana.
* Buat dasbor kustom yang menampilkan metrik `NetworkIn` dan kueri log teks dari log group `Suricata-Logs`.
* Tambahkan panel visualisasi Bar Gauge berbasis kueri analitik CloudWatch Logs Insights untuk merangking dan menampilkan 5 Alamat IP penyerang teratas secara waktu nyata.

## Simulasi Pengujian (Red Teaming)
Untuk memvalidasi sistem, peladen penyerang (Attacker) dapat menggunakan utilitas Nmap untuk memicu sensor deteksi awan dan lokal.
Gunakan perintah berikut pada terminal penyerang:
```bash
sudo nmap -Pn -sS -p 1-65535 -T4 -A -v [IP_PRIVATE_TARGET]
