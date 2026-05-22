#!/bin/bash

# =====================================================
# Ultimate Web Scanner - بدون تحميل تلقائي
# =====================================================
# Usage: ./ultimate_web_scanner_no_install.sh https://example.com
# =====================================================

# الألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# المتغيرات
TARGET="$1"
DOMAIN=$(echo "$TARGET" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${DOMAIN}_scan_${TIMESTAMP}"
LOG_FILE="$OUTPUT_DIR/scan_log.txt"

# قوائم الكلمات (استخدم الموجودة فقط)
COMMON_WORDLIST="/usr/share/wordlists/dirb/common.txt"
MEDIUM_WORDLIST="/usr/share/wordlists/dirb/directory-list-2.3-medium.txt"

# إنشاء المجلدات
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/reports"
mkdir -p "$OUTPUT_DIR/urls"
mkdir -p "$OUTPUT_DIR/vulnerabilities"

# =====================================================
# دوال مساعدة
# =====================================================
log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                         Ultimate Web Scanner v3.0                            ║"
    echo "║                    Automated Web Security Testing Tool                       ║"
    echo "╠══════════════════════════════════════════════════════════════════════════════╣"
    echo "║  [!] USE ONLY ON WEBSITES YOU OWN OR HAVE PERMISSION TO TEST                ║"
    echo "║  [!] MAKE SURE ALL TOOLS ARE INSTALLED BEFORE RUNNING                        ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_tools() {
    log_info "Checking available tools (no installation)..."
    
    MISSING=0
    TOOLS=("nmap" "whatweb" "wafw00f" "gobuster" "ffuf" "nuclei" "subfinder" "httpx" "nikto" "sqlmap" "jq" "curl" "dig" "whois")
    
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_success "$tool ✓"
        else
            log_warning "$tool ✗ (not found)"
            MISSING=1
        fi
    done
    
    if [ $MISSING -eq 1 ]; then
        echo ""
        log_warning "Some tools are missing. Install them manually with:"
        echo "  sudo apt install nmap whatweb wafw00f gobuster ffuf nuclei subfinder httpx nikto sqlmap jq dnsutils whois"
        echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo ""
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# =====================================================
# المرحلة 1: المعلومات الأساسية
# =====================================================
phase1_basic_info() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 1: جمع المعلومات الأساسية"
    log "═══════════════════════════════════════════════════════════════"
    
    if command -v whois &> /dev/null; then
        log_info "Fetching WHOIS information..."
        whois "$DOMAIN" > "$OUTPUT_DIR/01_whois.txt" 2>/dev/null || echo "No WHOIS data" > "$OUTPUT_DIR/01_whois.txt"
    else
        echo "whois not installed" > "$OUTPUT_DIR/01_whois.txt"
    fi
    
    if command -v dig &> /dev/null; then
        log_info "Fetching DNS records..."
        {
            echo "=== A Records ==="
            dig "$DOMAIN" A +short
            echo ""
            echo "=== MX Records ==="
            dig "$DOMAIN" MX +short
            echo ""
            echo "=== NS Records ==="
            dig "$DOMAIN" NS +short
        } > "$OUTPUT_DIR/02_dns_records.txt"
    else
        echo "dig not installed" > "$OUTPUT_DIR/02_dns_records.txt"
    fi
    
    log_info "Fetching HTTP Headers..."
    curl -s -I -L "$TARGET" > "$OUTPUT_DIR/03_http_headers.txt" 2>/dev/null
    
    if command -v whatweb &> /dev/null; then
        log_info "Detecting technologies..."
        whatweb --no-errors -a 3 "$TARGET" > "$OUTPUT_DIR/04_technologies.txt" 2>/dev/null
    else
        echo "whatweb not installed" > "$OUTPUT_DIR/04_technologies.txt"
    fi
    
    if command -v wafw00f &> /dev/null; then
        log_info "Detecting WAF..."
        wafw00f "$TARGET" > "$OUTPUT_DIR/05_waf_detection.txt" 2>/dev/null
    else
        echo "wafw00f not installed" > "$OUTPUT_DIR/05_waf_detection.txt"
    fi
    
    log_success "Phase 1 completed"
}

# =====================================================
# المرحلة 2: فحص الشبكة والمنافذ
# =====================================================
phase2_network_scan() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 2: فحص الشبكة والمنافذ"
    log "═══════════════════════════════════════════════════════════════"
    
    if command -v nmap &> /dev/null; then
        log_info "Scanning open ports..."
        nmap -sS -sV -T4 -p- --min-rate=1000 "$DOMAIN" -oN "$OUTPUT_DIR/06_port_scan.txt" 2>/dev/null
        nmap -sS -sV -T4 -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017 "$DOMAIN" -oN "$OUTPUT_DIR/07_top_ports.txt" 2>/dev/null
    else
        echo "nmap not installed" > "$OUTPUT_DIR/06_port_scan.txt"
    fi
    
    log_success "Phase 2 completed"
}

# =====================================================
# المرحلة 3: اكتشاف النطاقات الفرعية
# =====================================================
phase3_subdomains() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 3: اكتشاف النطاقات الفرعية"
    log "═══════════════════════════════════════════════════════════════"
    
    if command -v subfinder &> /dev/null; then
        log_info "Running subfinder..."
        subfinder -d "$DOMAIN" -silent > "$OUTPUT_DIR/09_subfinder.txt" 2>/dev/null
    else
        echo "subfinder not installed" > "$OUTPUT_DIR/09_subfinder.txt"
    fi
    
    # دمج النتائج
    cat "$OUTPUT_DIR/09_subfinder.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/12_all_subdomains.txt"
    
    if command -v httpx &> /dev/null; then
        log_info "Checking alive subdomains..."
        cat "$OUTPUT_DIR/12_all_subdomains.txt" | httpx -silent -status-code -timeout 3 > "$OUTPUT_DIR/13_alive_subdomains.txt" 2>/dev/null
    else
        cp "$OUTPUT_DIR/12_all_subdomains.txt" "$OUTPUT_DIR/13_alive_subdomains.txt" 2>/dev/null
    fi
    
    SUB_COUNT=$(cat "$OUTPUT_DIR/12_all_subdomains.txt" 2>/dev/null | wc -l)
    log_success "Found $SUB_COUNT subdomains"
    
    log_success "Phase 3 completed"
}

# =====================================================
# المرحلة 4: فحص الملفات والمجلدات
# =====================================================
phase4_directory_busting() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 4: فحص الملفات والمجلدات الحساسة"
    log "═══════════════════════════════════════════════════════════════"
    
    if command -v gobuster &> /dev/null && [ -f "$COMMON_WORDLIST" ]; then
        log_info "Scanning for common files..."
        gobuster dir -u "$TARGET" -w "$COMMON_WORDLIST" -t 20 -o "$OUTPUT_DIR/14_gobuster_common.txt" -b 404 -q 2>/dev/null
        
        log_info "Scanning with extensions..."
        gobuster dir -u "$TARGET" -w "$COMMON_WORDLIST" -x php,bak,old,sql,zip,tar,gz,env,json,yml,yaml,conf,config,inc,log,txt,md -t 20 -o "$OUTPUT_DIR/15_gobuster_extensions.txt" -b 404 -q 2>/dev/null
    else
        echo "gobuster not installed or wordlist missing" > "$OUTPUT_DIR/14_gobuster_common.txt"
    fi
    
    log_success "Phase 4 completed"
}

# =====================================================
# المرحلة 5: استخراج الروابط
# =====================================================
phase5_url_extraction() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 5: استخراج الروابط"
    log "═══════════════════════════════════════════════════════════════"
    
    log_info "Extracting URLs from Wayback Machine..."
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=json&fl=original&collapse=urlkey&limit=50000" | jq -r '.[1:][] | .[0]' 2>/dev/null > "$OUTPUT_DIR/18_wayback_urls.txt"
    
    # دمج الروابط
    cat "$OUTPUT_DIR/18_wayback_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/21_all_urls.txt"
    
    # استخراج الروابط ذات المعاملات
    grep -E '\?[a-zA-Z0-9_]+=' "$OUTPUT_DIR/21_all_urls.txt" 2>/dev/null > "$OUTPUT_DIR/22_parameterized_urls.txt"
    
    URL_COUNT=$(cat "$OUTPUT_DIR/21_all_urls.txt" 2>/dev/null | wc -l)
    PARAM_COUNT=$(cat "$OUTPUT_DIR/22_parameterized_urls.txt" 2>/dev/null | wc -l)
    log_success "Found $URL_COUNT total URLs, $PARAM_COUNT with parameters"
    
    log_success "Phase 5 completed"
}

# =====================================================
# المرحلة 6: فحص الثغرات (Nuclei)
# =====================================================
phase6_nuclei_scan() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 6: فحص الثغرات"
    log "═══════════════════════════════════════════════════════════════"
    
    if command -v nuclei &> /dev/null; then
        log_info "Running nuclei scan..."
        nuclei -target "$TARGET" -severity low,medium,high,critical -o "$OUTPUT_DIR/24_nuclei_all.txt" -silent 2>/dev/null
        nuclei -target "$TARGET" -severity critical,high -o "$OUTPUT_DIR/25_nuclei_critical.txt" -silent 2>/dev/null
    else
        echo "nuclei not installed" > "$OUTPUT_DIR/24_nuclei_all.txt"
    fi
    
    VULN_COUNT=$(cat "$OUTPUT_DIR/24_nuclei_all.txt" 2>/dev/null | wc -l)
    log_success "Found $VULN_COUNT vulnerabilities"
    
    log_success "Phase 6 completed"
}

# =====================================================
# المرحلة 7: فحص SQL Injection
# =====================================================
phase7_sqli_scan() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 7: فحص SQL Injection"
    log "═══════════════════════════════════════════════════════════════"
    
    if [ ! -f "$OUTPUT_DIR/22_parameterized_urls.txt" ]; then
        log_warning "No parameterized URLs found, skipping SQLi scan"
        return
    fi
    
    if command -v sqlmap &> /dev/null; then
        mkdir -p "$OUTPUT_DIR/sqlmap"
        log_info "Testing parameterized URLs with SQLMap..."
        
        while IFS= read -r url; do
            if [ -n "$url" ]; then
                sqlmap -u "$url" --batch --smart --level=1 --risk=1 --output-dir="$OUTPUT_DIR/sqlmap" --no-cast --threads=5 2>/dev/null >> "$OUTPUT_DIR/30_sqlmap_results.txt"
            fi
        done < <(head -30 "$OUTPUT_DIR/22_parameterized_urls.txt")
        
        grep -i "vulnerable" "$OUTPUT_DIR/30_sqlmap_results.txt" 2>/dev/null > "$OUTPUT_DIR/31_sqli_vulnerable.txt"
    else
        echo "sqlmap not installed" > "$OUTPUT_DIR/30_sqlmap_results.txt"
    fi
    
    SQLI_COUNT=$(cat "$OUTPUT_DIR/31_sqli_vulnerable.txt" 2>/dev/null | wc -l)
    log_success "Found $SQLI_COUNT potential SQL injection vulnerabilities"
    
    log_success "Phase 7 completed"
}

# =====================================================
# المرحلة 8: فحص Nikto
# =====================================================
phase8_nikto_scan() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 8: فحص Nikto"
    log "═══════════════════════════════════════════════════════════════"
    
    if command -v nikto &> /dev/null; then
        log_info "Running Nikto scan (this may take a while)..."
        nikto -h "$TARGET" -Format txt -o "$OUTPUT_DIR/33_nikto_scan.txt" 2>/dev/null
    else
        echo "nikto not installed" > "$OUTPUT_DIR/33_nikto_scan.txt"
    fi
    
    log_success "Phase 8 completed"
}

# =====================================================
# المرحلة 9: فحص SSL
# =====================================================
phase9_ssl_scan() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 9: فحص SSL/TLS"
    log "═══════════════════════════════════════════════════════════════"
    
    log_info "Checking SSL certificate..."
    echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN":443 2>/dev/null | openssl x509 -text > "$OUTPUT_DIR/35_ssl_certificate.txt" 2>/dev/null
    
    log_success "Phase 9 completed"
}

# =====================================================
# المرحلة 10: فحص سوء التكوين
# =====================================================
phase10_misconfig_scan() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 10: فحص سوء التكوين"
    log "═══════════════════════════════════════════════════════════════"
    
    log_info "Checking for exposed files..."
    curl -s "$TARGET/.git/HEAD" >> "$OUTPUT_DIR/38_exposed_git.txt" 2>/dev/null
    curl -s "$TARGET/.env" >> "$OUTPUT_DIR/39_exposed_env.txt" 2>/dev/null
    
    log_info "Checking security headers..."
    curl -s -I "$TARGET" | grep -E "X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security" > "$OUTPUT_DIR/41_security_headers.txt"
    
    log_success "Phase 10 completed"
}

# =====================================================
# المرحلة 11: التقرير النهائي
# =====================================================
phase11_final_report() {
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 11: إنشاء التقرير النهائي"
    log "═══════════════════════════════════════════════════════════════"
    
    REPORT_FILE="$OUTPUT_DIR/FINAL_REPORT.txt"
    
    {
        echo "================================================================================"
        echo "                         FINAL SCAN REPORT"
        echo "================================================================================"
        echo ""
        echo "Target: $TARGET"
        echo "Domain: $DOMAIN"
        echo "Scan Date: $(date)"
        echo "Output Directory: $OUTPUT_DIR"
        echo ""
        echo "================================================================================"
        echo "                         SCAN SUMMARY"
        echo "================================================================================"
        echo ""
        
        echo "[+] SUBDOMAINS:"
        echo "    Total found: $(cat "$OUTPUT_DIR/12_all_subdomains.txt" 2>/dev/null | wc -l)"
        echo ""
        
        echo "[+] URLs:"
        echo "    Total URLs: $(cat "$OUTPUT_DIR/21_all_urls.txt" 2>/dev/null | wc -l)"
        echo "    URLs with parameters: $(cat "$OUTPUT_DIR/22_parameterized_urls.txt" 2>/dev/null | wc -l)"
        echo ""
        
        echo "[+] VULNERABILITIES:"
        echo "    Critical/High: $(cat "$OUTPUT_DIR/25_nuclei_critical.txt" 2>/dev/null | wc -l)"
        echo "    Total: $(cat "$OUTPUT_DIR/24_nuclei_all.txt" 2>/dev/null | wc -l)"
        echo ""
        
        echo "[+] SQL Injection:"
        echo "    Vulnerable endpoints: $(cat "$OUTPUT_DIR/31_sqli_vulnerable.txt" 2>/dev/null | wc -l)"
        echo ""
        
        echo "[+] TECHNOLOGIES:"
        head -10 "$OUTPUT_DIR/04_technologies.txt" 2>/dev/null
        echo ""
        
        echo "[+] OPEN PORTS:"
        grep "open" "$OUTPUT_DIR/06_port_scan.txt" 2>/dev/null | head -10
        echo ""
        
        echo "================================================================================"
        echo "                         RECOMMENDATIONS"
        echo "================================================================================"
        echo ""
        
        if [ -s "$OUTPUT_DIR/31_sqli_vulnerable.txt" ]; then
            echo "[!] SQL Injection vulnerabilities detected! Fix immediately."
        fi
        
        if [ -s "$OUTPUT_DIR/25_nuclei_critical.txt" ]; then
            echo "[!] Critical vulnerabilities detected! Review Nuclei results."
        fi
        
        if [ -s "$OUTPUT_DIR/38_exposed_git.txt" ]; then
            echo "[!] .git folder exposed! Remove it from production."
        fi
        
        if [ -s "$OUTPUT_DIR/39_exposed_env.txt" ]; then
            echo "[!] .env file exposed! Critical security risk!"
        fi
        
        echo ""
        echo "================================================================================"
        echo "                         END OF REPORT"
        echo "================================================================================"
        
    } > "$REPORT_FILE"
    
    log_success "Final report saved to: $REPORT_FILE"
}

# =====================================================
# التشغيل الرئيسي
# =====================================================
main() {
    print_banner
    
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Usage: $0 <target_url>${NC}"
        echo -e "${YELLOW}Example: $0 https://example.com${NC}"
        exit 1
    fi
    
    log "Target: $TARGET"
    log "Output Directory: $OUTPUT_DIR"
    log ""
    
    check_tools
    
    START_TIME=$(date +%s)
    
    phase1_basic_info
    phase2_network_scan
    phase3_subdomains
    phase4_directory_busting
    phase5_url_extraction
    phase6_nuclei_scan
    phase7_sqli_scan
    phase8_nikto_scan
    phase9_ssl_scan
    phase10_misconfig_scan
    phase11_final_report
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    MINUTES=$((DURATION / 60))
    SECONDS=$((DURATION % 60))
    
    log ""
    log "═══════════════════════════════════════════════════════════════"
    log "                    SCAN COMPLETED SUCCESSFULLY"
    log "═══════════════════════════════════════════════════════════════"
    log "Total time: ${MINUTES}m ${SECONDS}s"
    log "Results saved in: $OUTPUT_DIR"
    log "Final report: $OUTPUT_DIR/FINAL_REPORT.txt"
    log "═══════════════════════════════════════════════════════════════"
    
    echo ""
    echo -e "${GREEN}To view the final report:${NC}"
    echo -e "  cat $OUTPUT_DIR/FINAL_REPORT.txt"
}

# تشغيل السكربت
main "$@"