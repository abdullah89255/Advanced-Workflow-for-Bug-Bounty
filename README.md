# Advanced-Workflow-for-Bug-Bounty
An **Advanced Bug Bounty Workflow** integrates tools and techniques for subdomain enumeration, validation, port scanning, vulnerability discovery, and reporting. Below is an enhanced workflow with step-by-step guidance, detailed explanations, and commands.

---

### **Advanced Bug Bounty Workflow**

#### **1. Subdomain Enumeration**
Subdomain enumeration is the first step to identify attack surfaces.

- **Tools Used:** Findomain, Amass, Subfinder, Assetfinder
- **Commands:**

```bash
# Run Findomain
findomain -t example.com -o -u findomain_results.txt

# Run Subfinder
subfinder -d example.com -o subfinder_results.txt

# Run Amass Passive Mode
amass enum -passive -d example.com -o amass_results.txt

# Merge Results and Remove Duplicates
cat findomain_results.txt subfinder_results.txt amass_results.txt | sort -u > all_subdomains.txt
```

---

#### **2. DNS Validation**
Validate discovered subdomains to ensure they resolve to active IP addresses.

- **Tools Used:** DNSx, MassDNS
- **Commands:**

```bash
# Validate Subdomains with DNSx
dnsx -l all_subdomains.txt -o validated_subdomains.txt

# Alternatively, Validate with MassDNS
massdns -r resolvers.txt -t A -o S -w massdns_results.txt all_subdomains.txt
```

---

#### **3. HTTP Probing**
Identify live HTTP servers from validated subdomains.

- **Tools Used:** Httprobe, HTTPx
- **Commands:**

```bash
# Use Httprobe
cat validated_subdomains.txt | httprobe -prefer-https > live_http.txt

# Use HTTPx for More Details
httpx -l validated_subdomains.txt -o live_http_detailed.txt
```

---

#### **4. Port Scanning**
Perform fast scans to identify open ports on discovered subdomains.

- **Tools Used:** Naabu, Masscan, Nmap
- **Commands:**

```bash
# Run Naabu for Fast Port Scanning
naabu -iL validated_subdomains.txt -o open_ports.txt

# Use Masscan for Faster Scanning (Rate-Limited)
masscan -iL validated_subdomains.txt -p80,443 --rate=1000 -oX masscan_results.xml

# Use Nmap for Detailed Scanning
nmap -iL validated_subdomains.txt -p80,443 -A -oN nmap_results.txt
```

---

#### **5. Vulnerability Scanning**
Scan for common vulnerabilities on live subdomains.

- **Tools Used:** Nuclei, Nikto
- **Commands:**

```bash
# Scan with Nuclei
nuclei -l live_http.txt -t nuclei-templates/ -o nuclei_results.txt

# Run Nikto for Basic Web Vulnerability Checks
nikto -h live_http.txt -output nikto_results.txt
```

---

#### **6. Subdomain Takeover Detection**
Check for vulnerable subdomains that might be subject to takeover.

- **Tools Used:** Subjack, Subzy
- **Commands:**

```bash
# Use Subjack
subjack -w validated_subdomains.txt -t 50 -timeout 30 -o takeover_results.txt -ssl

# Use Subzy
subzy -targets validated_subdomains.txt -output takeover_results.txt
```

---

#### **7. Content Discovery**
Discover hidden endpoints, directories, and files.

- **Tools Used:** FFUF, Dirsearch
- **Commands:**

```bash
# Directory Brute-forcing with FFUF
ffuf -u https://example.com/FUZZ -w wordlist.txt -o ffuf_results.json

# Use Dirsearch for Recursive Directory Search
dirsearch -u https://example.com -e php,html,js -o dirsearch_results.txt
```

---

#### **8. Automate Screenshots**
Capture screenshots of live subdomains for visual reconnaissance.

- **Tools Used:** Eyewitness, Gowitness
- **Commands:**

```bash
# Use Eyewitness
eyewitness --web -f live_http.txt -d screenshots/

# Use Gowitness
gowitness file -f live_http.txt --destination screenshots/
```

---

#### **9. Analyze Results**
Combine all the data for meaningful analysis.

- **Combine Findings:**

```bash
cat nuclei_results.txt nikto_results.txt takeover_results.txt > consolidated_findings.txt
```

---

### **Putting It All Together: Full Automation Script**

Here is a Bash script that automates the above workflow:

```bash
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
```

---

### **Execution**
1. Save the script as `bug_bounty.sh`.
2. Make it executable:
   ```bash
   chmod +x bug_bounty.sh
   ```
3. Run the script:
   ```bash
   ./bug_bounty.sh example.com
   ```

---

### **Enhancements for Workflow**
1. **Slack or Email Alerts**: Notify yourself when the workflow completes or detects critical vulnerabilities.
2. **Cron Jobs**: Schedule regular scans using `cron`.
3. **Cloud Environments**: Run the workflow in AWS or GCP for scalability.

Let me know if you'd like to expand on any specific tool integration or further optimize this workflow!


Your script is well-structured for a bug bounty workflow, but there are a few areas where it can be improved or expanded to address common vulnerabilities like XSS, LFI, SQLi, and IDOR. Below are the fixes and additions:

---

### **Fixes and Improvements:**

1. **Error Handling**:
   - Add checks to ensure tools like `findomain`, `subfinder`, `amass`, etc., are installed before execution.
   - Example:
     ```bash
     if ! command -v findomain &> /dev/null; then
         echo "Error: findomain is not installed. Please install it first."
         exit 1
     fi
     ```

2. **Output Directory Cleanup**:
   - Ensure the output directory is clean before starting. Add:
     ```bash
     rm -rf $OUTPUT_DIR/*
     ```

3. **Parallel Execution**:
   - Some steps (like subdomain enumeration) can run in parallel to save time. Use `&` and `wait`:
     ```bash
     findomain -t $TARGET -o -u $OUTPUT_DIR/findomain.txt &
     subfinder -d $TARGET -o $OUTPUT_DIR/subfinder.txt &
     amass enum -passive -d $TARGET -o $OUTPUT_DIR/amass.txt &
     wait
     ```

4. **Logging**:
   - Redirect tool outputs to log files for debugging:
     ```bash
     findomain -t $TARGET -o -u $OUTPUT_DIR/findomain.txt > $OUTPUT_DIR/findomain.log 2>&1
     ```

---

### **Additions for Common Vulnerabilities:**

1. **XSS (Cross-Site Scripting)**:
   - Use tools like `dalfox` or `xsstrike` to scan for XSS vulnerabilities:
     ```bash
     echo "[*] Scanning for XSS..."
     dalfox file $OUTPUT_DIR/live_http.txt -o $OUTPUT_DIR/xss_results.txt
     ```

2. **LFI (Local File Inclusion)**:
   - Use `ffuf` with LFI-specific wordlists:
     ```bash
     echo "[*] Scanning for LFI..."
     ffuf -u https://$TARGET/FUZZ -w lfi_wordlist.txt -o $OUTPUT_DIR/lfi_results.json
     ```

3. **SQLi (SQL Injection)**:
   - Use `sqlmap` or `ffuf` with SQLi payloads:
     ```bash
     echo "[*] Scanning for SQLi..."
     sqlmap -m $OUTPUT_DIR/live_http.txt --batch --output-dir=$OUTPUT_DIR/sqlmap_results
     ```

4. **IDOR (Insecure Direct Object Reference)**:
   - Manual testing is often required, but you can use `arjun` to identify parameters:
     ```bash
     echo "[*] Identifying Parameters for IDOR Testing..."
     arjun -i $OUTPUT_DIR/live_http.txt -o $OUTPUT_DIR/arjun_results.json
     ```

5. **Broken Authentication**:
   - Use `hydra` or `burp suite` for brute-forcing (ensure you have permission):
     ```bash
     echo "[*] Testing for Broken Authentication..."
     hydra -L users.txt -P passwords.txt $TARGET http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -o $OUTPUT_DIR/hydra_results.txt
     ```

6. **CSRF (Cross-Site Request Forgery)**:
   - Use `csrf-tester` or manual testing with Burp Suite.

---

### **Final Script with Additions:**

```bash
#!/bin/bash

TARGET=$1
OUTPUT_DIR="./bug_bounty_results/$TARGET"

# Cleanup and create output directory
rm -rf $OUTPUT_DIR/*
mkdir -p $OUTPUT_DIR

echo "[*] Starting Bug Bounty Workflow for $TARGET"

# Check for required tools
REQUIRED_TOOLS=("findomain" "subfinder" "amass" "dnsx" "httpx" "naabu" "nuclei" "subjack" "ffuf" "gowitness" "dalfox" "sqlmap" "arjun" "hydra")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is not installed. Please install it first."
        exit 1
    fi
done

# Step 1: Subdomain Enumeration (Parallel)
echo "[*] Enumerating Subdomains..."
findomain -t $TARGET -o -u $OUTPUT_DIR/findomain.txt > $OUTPUT_DIR/findomain.log 2>&1 &
subfinder -d $TARGET -o $OUTPUT_DIR/subfinder.txt > $OUTPUT_DIR/subfinder.log 2>&1 &
amass enum -passive -d $TARGET -o $OUTPUT_DIR/amass.txt > $OUTPUT_DIR/amass.log 2>&1 &
wait
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

# Step 2: DNS Validation
echo "[*] Validating DNS..."
dnsx -l $OUTPUT_DIR/all_subdomains.txt -o $OUTPUT_DIR/validated_subdomains.txt > $OUTPUT_DIR/dnsx.log 2>&1

# Step 3: HTTP Probing
echo "[*] Probing HTTP Servers..."
httpx -l $OUTPUT_DIR/validated_subdomains.txt -o $OUTPUT_DIR/live_http.txt > $OUTPUT_DIR/httpx.log 2>&1

# Step 4: Port Scanning
echo "[*] Scanning Open Ports..."
naabu -iL $OUTPUT_DIR/validated_subdomains.txt -o $OUTPUT_DIR/open_ports.txt > $OUTPUT_DIR/naabu.log 2>&1

# Step 5: Vulnerability Scanning
echo "[*] Running Vulnerability Scans..."
nuclei -l $OUTPUT_DIR/live_http.txt -t nuclei-templates/ -o $OUTPUT_DIR/nuclei_results.txt > $OUTPUT_DIR/nuclei.log 2>&1

# Step 6: Subdomain Takeover Detection
echo "[*] Checking for Subdomain Takeovers..."
subjack -w $OUTPUT_DIR/validated_subdomains.txt -t 50 -timeout 30 -o $OUTPUT_DIR/takeover_results.txt -ssl > $OUTPUT_DIR/subjack.log 2>&1

# Step 7: Content Discovery
echo "[*] Discovering Content..."
ffuf -u https://$TARGET/FUZZ -w wordlist.txt -o $OUTPUT_DIR/ffuf_results.json > $OUTPUT_DIR/ffuf.log 2>&1

# Step 8: Screenshots
echo "[*] Capturing Screenshots..."
gowitness file -f $OUTPUT_DIR/live_http.txt --destination $OUTPUT_DIR/screenshots/ > $OUTPUT_DIR/gowitness.log 2>&1

# Step 9: XSS Scanning
echo "[*] Scanning for XSS..."
dalfox file $OUTPUT_DIR/live_http.txt -o $OUTPUT_DIR/xss_results.txt > $OUTPUT_DIR/dalfox.log 2>&1

# Step 10: LFI Scanning
echo "[*] Scanning for LFI..."
ffuf -u https://$TARGET/FUZZ -w lfi_wordlist.txt -o $OUTPUT_DIR/lfi_results.json > $OUTPUT_DIR/lfi_ffuf.log 2>&1

# Step 11: SQLi Scanning
echo "[*] Scanning for SQLi..."
sqlmap -m $OUTPUT_DIR/live_http.txt --batch --output-dir=$OUTPUT_DIR/sqlmap_results > $OUTPUT_DIR/sqlmap.log 2>&1

# Step 12: IDOR Parameter Identification
echo "[*] Identifying Parameters for IDOR Testing..."
arjun -i $OUTPUT_DIR/live_http.txt -o $OUTPUT_DIR/arjun_results.json > $OUTPUT_DIR/arjun.log 2>&1

# Step 13: Broken Authentication Testing
echo "[*] Testing for Broken Authentication..."
hydra -L users.txt -P passwords.txt $TARGET http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -o $OUTPUT_DIR/hydra_results.txt > $OUTPUT_DIR/hydra.log 2>&1

echo "[*] Bug Bounty Workflow Completed for $TARGET. Results saved in $OUTPUT_DIR"
```

---

### **Notes:**
- Ensure you have the necessary wordlists (`lfi_wordlist.txt`, `users.txt`, `passwords.txt`, etc.) in place.
- Adjust the script based on the tools you prefer or have available.
- Always confirm you have explicit permission before running any security tests.

Got it! Adding `waybackurls` to collect historical URLs and then analyzing them for vulnerabilities is a great addition. Below is the updated script with `waybackurls` integration and additional steps to analyze the collected URLs for common vulnerabilities like XSS, SQLi, LFI, etc.

---

### **Updated Script with `waybackurls` and Vulnerability Analysis:**

```bash
#!/bin/bash

TARGET=$1
OUTPUT_DIR="./bug_bounty_results/$TARGET"

# Cleanup and create output directory
rm -rf $OUTPUT_DIR/*
mkdir -p $OUTPUT_DIR

echo "[*] Starting Bug Bounty Workflow for $TARGET"

# Check for required tools
REQUIRED_TOOLS=("findomain" "subfinder" "amass" "dnsx" "httpx" "naabu" "nuclei" "subjack" "ffuf" "gowitness" "dalfox" "sqlmap" "arjun" "hydra" "waybackurls" "gau" "qsreplace" "gf")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is not installed. Please install it first."
        exit 1
    fi
done

# Step 1: Subdomain Enumeration (Parallel)
echo "[*] Enumerating Subdomains..."
findomain -t $TARGET -o -u $OUTPUT_DIR/findomain.txt > $OUTPUT_DIR/findomain.log 2>&1 &
subfinder -d $TARGET -o $OUTPUT_DIR/subfinder.txt > $OUTPUT_DIR/subfinder.log 2>&1 &
amass enum -passive -d $TARGET -o $OUTPUT_DIR/amass.txt > $OUTPUT_DIR/amass.log 2>&1 &
wait
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

# Step 2: DNS Validation
echo "[*] Validating DNS..."
dnsx -l $OUTPUT_DIR/all_subdomains.txt -o $OUTPUT_DIR/validated_subdomains.txt > $OUTPUT_DIR/dnsx.log 2>&1

# Step 3: HTTP Probing
echo "[*] Probing HTTP Servers..."
httpx -l $OUTPUT_DIR/validated_subdomains.txt -o $OUTPUT_DIR/live_http.txt > $OUTPUT_DIR/httpx.log 2>&1

# Step 4: Waybackurls for Historical URL Collection
echo "[*] Collecting Historical URLs..."
cat $OUTPUT_DIR/live_http.txt | waybackurls > $OUTPUT_DIR/waybackurls.txt
cat $OUTPUT_DIR/live_http.txt | gau > $OUTPUT_DIR/gau.txt
cat $OUTPUT_DIR/waybackurls.txt $OUTPUT_DIR/gau.txt | sort -u > $OUTPUT_DIR/all_urls.txt

# Step 5: Extract Parameters for Testing
echo "[*] Extracting Parameters..."
cat $OUTPUT_DIR/all_urls.txt | grep -Eo 'https?://[^/"]+' | sort -u > $OUTPUT_DIR/base_urls.txt
cat $OUTPUT_DIR/all_urls.txt | qsreplace -a > $OUTPUT_DIR/urls_with_params.txt

# Step 6: Vulnerability Scanning on Collected URLs
echo "[*] Scanning for XSS..."
dalfox file $OUTPUT_DIR/urls_with_params.txt -o $OUTPUT_DIR/xss_results.txt > $OUTPUT_DIR/dalfox.log 2>&1

echo "[*] Scanning for SQLi..."
sqlmap -m $OUTPUT_DIR/urls_with_params.txt --batch --output-dir=$OUTPUT_DIR/sqlmap_results > $OUTPUT_DIR/sqlmap.log 2>&1

echo "[*] Scanning for LFI..."
gf lfi $OUTPUT_DIR/all_urls.txt > $OUTPUT_DIR/lfi_results.txt

echo "[*] Scanning for SSRF..."
gf ssrf $OUTPUT_DIR/all_urls.txt > $OUTPUT_DIR/ssrf_results.txt

echo "[*] Scanning for Open Redirects..."
gf redirect $OUTPUT_DIR/all_urls.txt > $OUTPUT_DIR/redirect_results.txt

# Step 7: Port Scanning
echo "[*] Scanning Open Ports..."
naabu -iL $OUTPUT_DIR/validated_subdomains.txt -o $OUTPUT_DIR/open_ports.txt > $OUTPUT_DIR/naabu.log 2>&1

# Step 8: Nuclei for Vulnerability Scanning
echo "[*] Running Nuclei Scans..."
nuclei -l $OUTPUT_DIR/live_http.txt -t nuclei-templates/ -o $OUTPUT_DIR/nuclei_results.txt > $OUTPUT_DIR/nuclei.log 2>&1

# Step 9: Subdomain Takeover Detection
echo "[*] Checking for Subdomain Takeovers..."
subjack -w $OUTPUT_DIR/validated_subdomains.txt -t 50 -timeout 30 -o $OUTPUT_DIR/takeover_results.txt -ssl > $OUTPUT_DIR/subjack.log 2>&1

# Step 10: Content Discovery
echo "[*] Discovering Content..."
ffuf -u https://$TARGET/FUZZ -w wordlist.txt -o $OUTPUT_DIR/ffuf_results.json > $OUTPUT_DIR/ffuf.log 2>&1

# Step 11: Screenshots
echo "[*] Capturing Screenshots..."
gowitness file -f $OUTPUT_DIR/live_http.txt --destination $OUTPUT_DIR/screenshots/ > $OUTPUT_DIR/gowitness.log 2>&1

# Step 12: Broken Authentication Testing
echo "[*] Testing for Broken Authentication..."
hydra -L users.txt -P passwords.txt $TARGET http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -o $OUTPUT_DIR/hydra_results.txt > $OUTPUT_DIR/hydra.log 2>&1

echo "[*] Bug Bounty Workflow Completed for $TARGET. Results saved in $OUTPUT_DIR"
```

---

### **Key Additions:**

1. **`waybackurls` and `gau`**:
   - Collects historical URLs from Wayback Machine and other sources.
   - Combines results into `all_urls.txt`.

2. **Parameter Extraction**:
   - Uses `qsreplace` to extract and normalize parameters for testing.

3. **Vulnerability Scanning on URLs**:
   - **XSS**: Uses `dalfox` on URLs with parameters.
   - **SQLi**: Uses `sqlmap` on URLs with parameters.
   - **LFI/SSRF/Open Redirects**: Uses `gf` (Grep for Bugs) to filter URLs for specific patterns.

4. **Additional Tools**:
   - `gf`: A wrapper around `grep` to filter URLs for specific vulnerabilities (LFI, SSRF, etc.).
   - `qsreplace`: For manipulating query strings.

---

### **Notes:**
- Ensure you have the necessary tools (`waybackurls`, `gau`, `gf`, `qsreplace`) installed.
- Adjust wordlists (`wordlist.txt`, `users.txt`, `passwords.txt`) as needed.
- For `gf`, you may need to set up patterns (e.g., `~/.gf/lfi.json`) for filtering.
- Always confirm you have explicit permission before running any security tests.

Let me know if you'd like further refinements!
