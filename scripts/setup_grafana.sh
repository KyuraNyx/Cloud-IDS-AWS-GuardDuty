#!/bin/bash
# Skrip Pemasangan Dasbor Grafana

echo "Memperbarui repositori paket..."
sudo apt-get update -y

echo "Menginstal Grafana..."
sudo apt-get install grafana -y

echo "Menjalankan dan mengaktifkan layanan Grafana di latar belakang..."
sudo systemctl enable --now grafana-server

echo "Pemasangan selesai. Grafana berjalan pada port 3000."
