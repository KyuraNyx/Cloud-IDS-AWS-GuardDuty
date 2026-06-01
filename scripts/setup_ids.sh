#!/bin/bash
# Skrip Pemasangan Host-Based IDS (Suricata & CloudWatch Agent)

echo "Memperbarui repositori..."
sudo apt-get update -y

echo "Menginstal Suricata..."
sudo apt-get install suricata -y

echo "Mengunduh CloudWatch Agent..."
wget https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb

echo "Pemasangan selesai. Silakan muat aturan lokal dan konfigurasi agen."
