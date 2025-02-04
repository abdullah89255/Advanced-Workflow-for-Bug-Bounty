#!/bin/bash

TARGET=$1
OUTPUT_DIR="./bug_bounty_results/$TARGET"

mkdir -p $OUTPUT_DIR

echo "[*] Starting Bug Bounty Workflow for $TARGET"

# Step 1: Subdomain Enumeration
echo "[*] Enumerating Subdomains..."
findomain -t $TARGET -o -u $OUTPUT_DIR/findomain.txt
subfinder -d $TARGET -o $OUTPUT_DIR/subfinder.txt
amass enum -passive -d $TARGET -o $OUTPUT_DIR/amass.txt
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

# Step 2: DNS Validation
echo "[*] Validating DNS..."
dnsx -l $OUTPUT_DIR/all_subdomains.txt -o $OUTPUT_DIR/validated_subdomains.txt

# Step 3: HTTP Probing
echo "[*] Probing HTTP Servers..."
httpx -l $OUTPUT_DIR/validated_subdomains.txt -o $OUTPUT_DIR/live_http.txt

# Step 4: Port Scanning
echo "[*] Scanning Open Ports..."
naabu -iL $OUTPUT_DIR/validated_subdomains.txt -o $OUTPUT_DIR/open_ports.txt

# Step 5: Vulnerability Scanning
echo "[*] Running Vulnerability Scans..."
nuclei -l $OUTPUT_DIR/live_http.txt -t nuclei-templates/ -o $OUTPUT_DIR/nuclei_results.txt

# Step 6: Subdomain Takeover Detection
echo "[*] Checking for Subdomain Takeovers..."
subjack -w $OUTPUT_DIR/validated_subdomains.txt -t 50 -timeout 30 -o $OUTPUT_DIR/takeover_results.txt -ssl

# Step 7: Content Discovery
echo "[*] Discovering Content..."
ffuf -u https://$TARGET/FUZZ -w wordlist.txt -o $OUTPUT_DIR/ffuf_results.json

# Step 8: Screenshots
echo "[*] Capturing Screenshots..."
gowitness file -f $OUTPUT_DIR/live_http.txt --destination $OUTPUT_DIR/screenshots/

echo "[*] Bug Bounty Workflow Completed for $TARGET. Results saved in $OUTPUT_DIR"
