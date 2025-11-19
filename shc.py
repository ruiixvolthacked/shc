#!/usr/bin/env python3
# Security Headers Checker by RuiiXploit
# Usage: python shc.py -d https://example.com

import requests
import argparse
import os
from datetime import datetime

# ==== WARNA ====
R = "\033[91m"   # Merah
G = "\033[92m"   # Hijau
Y = "\033[93m"   # Kuning
C = "\033[96m"   # Cyan
W = "\033[97m"   # Putih
B = "\033[94m"   # Biru
RST = "\033[0m"  # Reset

# ==== BANNER ====
def banner():
    print(C + "=================================" + RST)
    print(f"> shc.py {Y}RuiiXploit{RST}.")
    print("check security headers on a webserver")
    print(C + "=================================" + RST + "\n")

# ==== SAVE RESULT ====
def save_reports(html_content, pdf_content):
    print()
    directory = input("Masukkan direktori untuk menyimpan hasil: ")
    if not os.path.isdir(directory):
        print(R + "[!] Direktori tidak valid." + RST)
        return

    html_path = os.path.join(directory, "security_headers_report.html")
    pdf_path = os.path.join(directory, "security_headers_report.pdf")

    # Simpan HTML
    with open(html_path, "w") as f:
        f.write(html_content)

    # Simpan PDF (sederhana, teks ke PDF)
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(pdf_path)
    textobject = c.beginText(20, 800)

    for line in pdf_content.split("\n"):
        textobject.textLine(line)
    c.drawText(textobject)
    c.save()

    print(G + f"[+] Crated PDF and HTML Summary:" + RST)
    print(f"    {html_path}")
    print(f"    {pdf_path}")

# ==== CEK HEADERS ====
def check_headers(url):
    print(C + "Starting Scanning\n" + RST)
    print(f"[*] Analyzing headers of {Y}{url}{RST}")

    try:
        r = requests.get(url, allow_redirects=True)
    except:
        print(R + "[!] Target tidak bisa diakses." + RST)
        return

    print(f"[*] Effective URL: {C}{r.url}{RST}\n")

    headers = r.headers

    # List header penting
    important_headers = {
        "X-XSS-Protection": False,
        "Content-Security-Policy": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
        "X-Frame-Options": False,
        "Strict-Transport-Security": False,
        "Public-Key-Pins": False,
        "X-Permitted-Cross-Domain-Policies": False
    }

    output_log = []
    html_report = "<h1>Security Headers Report</h1>"
    pdf_text = "Security Headers Report\n\n"

    for h in important_headers:
        if h in headers:
            val = headers[h]
            print(f"[*] Header {G}{h}{RST} is present! (Value: {val})")
            output_log.append(f"{h}: PRESENT ({val})")
            important_headers[h] = True
        else:
            print(f"[{R}!{RST}] Missing security header: {R}{h}{RST}")
            output_log.append(f"{h}: MISSING")

    print("")

    # Info Disclosure Headers
    info_headers = ["Server", "X-Powered-By"]

    found_disclosure = False
    for ih in info_headers:
        if ih in headers:
            found_disclosure = True
            print(f"[!] Information disclosure header detected: {Y}{ih}{RST} (Value: {headers[ih]})")

            output_log.append(f"{ih}: INFO DISCLOSURE ({headers[ih]})")

    if not found_disclosure:
        print(f"[*] {G}No information disclosure headers detected{RST}")

    print("")

    # Cache headers
    cache_headers = ["Pragma", "Cache-Control"]
    for ch in cache_headers:
        if ch in headers:
            print(f"[!] Cache control header {Y}{ch}{RST} is present! Value: {headers[ch]})")
            output_log.append(f"{ch}: Cache header ({headers[ch]})")

    # Summary
    print("-------------------------------------------")
    present_count = sum(1 for x in important_headers.values() if x)
    missing_count = len(important_headers) - present_count

    print(f"[!] Headers analyzed for {C}{r.url}{RST}")
    print(f"[+] There are {G}{present_count}{RST} security headers")
    print(f"[-] There are {R}{missing_count}{RST} missing security headers\n")

    # Siapkan laporan HTML dan PDF
    html_report += "<pre>" + "\n".join(output_log) + "</pre>"
    pdf_text += "\n".join(output_log)

    save_reports(html_report, pdf_text)

# ==== MAIN ====
if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Target domain", required=True)
    args = parser.parse_args()

    check_headers(args.domain)