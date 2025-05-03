import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from tabulate import tabulate
from colorama import Fore, Style, init
from fpdf import FPDF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import sys
from contextlib import contextmanager
from datetime import datetime
import os
from typing import Dict, List, Optional
from dataclasses import dataclass
import json
import time
import os
import json
import webbrowser
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse, parse_qs
from urllib.parse import urlparse, parse_qs, quote


@dataclass
class CVEDetails:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: str
    references: List[str]


class NVDApiClient:
    def __init__(self, api_key: str):

        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            "X-Api-Key": api_key,
            "User-Agent": "Mozilla/5.0 (compatible; VulnerabilityScanner/1.0)"
        }
        self.request_delay = 6  
    def get_cve_details(self, keyword: str, max_results: int = 5) -> List[CVEDetails]:
        
        try:
            
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results
            }
            
            time.sleep(self.request_delay)
            
            response = requests.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 403:
                print(f"API rate limit exceeded or authentication error: {response.text}")
                return []
                
            response.raise_for_status()
            data = response.json()
            
            print(f"Found {len(data.get('vulnerabilities', []))} CVEs matching '{keyword}'")
            
            cve_list = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                
                cvss_score = 0.0
                severity = "UNKNOWN"
                
                if cve.get("metrics", {}).get("cvssMetricV31"):
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                    cvss_data = metrics.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                elif cve.get("metrics", {}).get("cvssMetricV30"):
                    metrics = cve.get("metrics", {}).get("cvssMetricV30", [{}])[0]
                    cvss_data = metrics.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                elif cve.get("metrics", {}).get("cvssMetricV2"):
                    metrics = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0]
                    cvss_data = metrics.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    if cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                
                description = "No description available"
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "No description available")
                        break
                
                cve_details = CVEDetails(
                    cve_id=cve.get("id", "Unknown"),
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published_date=cve.get("published", "Unknown"),
                    references=[ref.get("url") for ref in cve.get("references", [])]
                )
                cve_list.append(cve_details)
            
            return cve_list
            
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to NVD API: {e}")
            return []
        except json.JSONDecodeError as e:
            print(f"Error parsing NVD API response: {e}")
            return []
        except Exception as e:
            print(f"Error fetching CVE details: {e}")
            return []


def get_vulnerability_cves(vulnerability_type: str, nvd_client: NVDApiClient) -> List[CVEDetails]:
    keyword_mapping = {
        "SQL injection vulnerability": "SQL injection",
        "Cross-site scripting (XSS) vulnerability": "cross-site scripting",
        "Insecure server configuration": "insecure configuration",
        "Open Redirect vulnerability": "open redirect",
        "Directory Traversal vulnerability": "path traversal",
        "Missing X-Frame-Options Header": "clickjacking X-Frame-Options",
        "Missing Content-Security-Policy Header": "Content-Security-Policy",
        "Missing Strict-Transport-Security Header": "HSTS transport security"
    }
    
    keyword = keyword_mapping.get(vulnerability_type, vulnerability_type)
    print(f"Searching for CVEs related to: {keyword}")
    return nvd_client.get_cve_details(keyword)


class OutputLogger:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.filename = filename
        self.log_file = None
        
    def start(self):
        self.log_file = open(self.filename, 'w', encoding='utf-8')
        sys.stdout = self
        
    def stop(self):
        sys.stdout = self.terminal
        if self.log_file:
            self.log_file.close()
            
    def write(self, message):
        self.terminal.write(message)
        if self.log_file:
            self.log_file.write(message)
            
    def flush(self):
        self.terminal.flush()
        if self.log_file:
            self.log_file.flush()


@contextmanager
def capture_output(filename):
    logger = OutputLogger(filename)
    logger.start()
    try:
        yield
    finally:
        logger.stop()


def scan_website(url, api_key: str, recipient_email: str):
    
    try:
        nvd_client = NVDApiClient(api_key)
        
        print(f"Discovering URLs on {url}...")
        discovered_urls = discover_urls(url)
        print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")
        for i, discovered_url in enumerate(discovered_urls, start=1):
            print(f"{i}. {discovered_url}")

        vulnerabilities_summary = []

        for page_url in discovered_urls:
            print(f"\nScanning {page_url}...")
            vulnerabilities = scan_url(page_url)
            
            if vulnerabilities:
                print(f"\n{Fore.RED}Vulnerabilities found on {page_url}:{Style.RESET_ALL}")
                
                for vulnerability, attack_method in vulnerabilities.items():
                    print(f"\n{Fore.YELLOW}Vulnerability: {vulnerability}{Style.RESET_ALL}")
                    print(f"Attack Method: {attack_method}")
                    
                    cve_details = get_vulnerability_cves(vulnerability, nvd_client)
                    
                    if cve_details:
                        print(f"\n{Fore.CYAN}Related CVEs:{Style.RESET_ALL}")
                        for cve in cve_details:
                            severity_color = Fore.GREEN
                            if cve.severity == "HIGH" or cve.severity == "CRITICAL":
                                severity_color = Fore.RED
                            elif cve.severity == "MEDIUM":
                                severity_color = Fore.YELLOW
                                
                            print(f"\nCVE ID: {cve.cve_id}")
                            print(f"Severity: {severity_color}{cve.severity}{Style.RESET_ALL}")
                            print(f"CVSS Score: {cve.cvss_score}")
                            print(f"Published: {cve.published_date}")
                            print(f"Description: {cve.description}")
                            
                            if cve.references:
                                print("References:")
                                for ref in cve.references[:3]:  # Limit to 3 references
                                    print(f"- {ref}")

                    summary_entry = [
                        page_url,
                        vulnerability,
                        attack_method,
                        cve_details[0].cve_id if cve_details else "N/A",
                        cve_details[0].severity if cve_details else "N/A",
                        f"{cve_details[0].cvss_score}" if cve_details else "N/A",
                        cve_details[0].published_date if cve_details else "N/A",
                        cve_details[0].description if cve_details else "N/A",
                        ", ".join(cve_details[0].references[:3]) if cve_details and cve_details[0].references else "N/A"
                    ]
                    vulnerabilities_summary.append(summary_entry)
            else:
                print(f"{Fore.GREEN}No vulnerabilities found on {page_url}{Style.RESET_ALL}")

        if vulnerabilities_summary:
            save_vulnerabilities_to_document(vulnerabilities_summary)
            generate_pdf_report(vulnerabilities_summary)
            if recipient_email:
                send_email_report(vulnerabilities_summary, recipient_email)
            save_vulnerabilities_to_json(vulnerabilities_summary)
        else:
            print(f"\n{Fore.GREEN}No vulnerabilities found on any of the URLs.{Style.RESET_ALL}")

    except Exception as e:
        print(f"\n{Fore.RED}An error occurred while scanning the website: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

        
def open_dashboard():
    dashboard_url = "https://vedanshpundir.github.io/CVEAnalyticDashboard/"
    print(f"{Fore.CYAN}Attempting to open dashboard URL: {dashboard_url}{Style.RESET_ALL}")
    try:
        response = requests.head(dashboard_url, timeout=10)
        if response.status_code == 200:
            print(f"{Fore.GREEN}Dashboard URL is accessible (HTTP 200){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Dashboard URL returned HTTP {response.status_code}{Style.RESET_ALL}")
        
        webbrowser.open_new_tab(dashboard_url)
        print(f"{Fore.GREEN}Command to open dashboard sent successfully{Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{Fore.RED}Failed to verify dashboard URL: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to open dashboard: {e}{Style.RESET_ALL}")
    finally:
        print(f"{Fore.CYAN}If the dashboard did not open, try manually visiting: {dashboard_url}{Style.RESET_ALL}")

def save_vulnerabilities_to_document(vulnerabilities_summary):
    
    headers = [
        "Page URL", "Vulnerability", "Attack Method", "CVE ID",
        "Severity", "CVSS Score", "Published Date", "Description", "References"
    ]
    
    table = tabulate(vulnerabilities_summary, headers, tablefmt="grid")

    filename = "vulnerabilities_summary.txt"
    with open(filename, "w", encoding="utf-8") as file:
        file.write("Vulnerability Scan Report\n")
        file.write("=" * 30 + "\n\n")
        file.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        file.write(table)
        file.write("\n\nReport generated successfully!")

    print(f"\n{Fore.GREEN}Vulnerabilities summary saved to {filename}{Style.RESET_ALL}")
    



def save_vulnerabilities_to_json(vulnerabilities_summary):
    
    json_data = []
    for i, row in enumerate(vulnerabilities_summary):
        json_data.append({
            "id": i + 1,
            "url": row[0],
            "vulnerability": row[1],
            "attackMethod": row[2],
            "cveId": row[3],
            "severity": row[4],
            "cvssScore": float(row[5]) if row[5] != "N/A" else 0.0
        })

    filename = "vulnerabilities_data.json"
    with open(filename, "w") as file:
        json.dump(json_data, file, indent=4)

    print(f"\n{Fore.GREEN}JSON data for dashboard saved to {filename}{Style.RESET_ALL}")
    

def generate_pdf_report(vulnerabilities_summary):
    
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Website Vulnerability Report', 0, 1, 'C')
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        pdf.ln(10)

        pdf.set_font('Arial', 'B', 12)
        pdf.cell(60, 10, 'Vulnerability', 1, 0, 'C')
        pdf.cell(60, 10, 'CVE ID', 1, 0, 'C')
        pdf.cell(30, 10, 'Severity', 1, 0, 'C')
        pdf.cell(30, 10, 'CVSS Score', 1, 1, 'C')

        pdf.set_font('Arial', '', 10)
        for row in vulnerabilities_summary:
            pdf.ln(5)
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 10, f"URL: {row[0]}", 0, 1)
            pdf.set_font('Arial', '', 10)
            
            pdf.cell(60, 10, row[1], 1, 0)
            pdf.cell(60, 10, row[3], 1, 0)
            pdf.cell(30, 10, row[4], 1, 0)
            pdf.cell(30, 10, row[5], 1, 1)
            
            pdf.cell(0, 10, f"Attack Method: {row[2]}", 0, 1)
            pdf.ln(5)

        pdf.output("vulnerability_report.pdf")
        print(f"{Fore.GREEN}PDF report generated: vulnerability_report.pdf{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error generating PDF report: {e}{Style.RESET_ALL}")


def send_email_report(vulnerabilities_summary, recipient_email: str):
    
    if not vulnerabilities_summary:
        print("No vulnerabilities to report.")
        return

    if not recipient_email:
        print(f"{Fore.YELLOW}No recipient email provided. Skipping email report.{Style.RESET_ALL}")
        return

    body = "Website Vulnerability Report\n\n"
    body += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    body += "Here are the vulnerabilities detected:\n\n"
    
    for row in vulnerabilities_summary:
        body += "------------------------------------------------------------\n"
        body += f"URL: {row[0]}\n"
        body += f"Vulnerability: {row[1]}\n"
        body += f"Attack Method: {row[2]}\n"
        body += f"CVE ID: {row[3]}\n"
        body += f"Severity: {row[4]}\n"
        body += f"CVSS Score: {row[5]}\n"
        body += "------------------------------------------------------------\n\n"

    file_name = "vulnerabilities_summary.txt"
    
    pdf_file = "vulnerability_report.pdf"
    attachments = []
    if os.path.exists(file_name):
        attachments.append((file_name, 'text/plain'))
    if os.path.exists(pdf_file):
        attachments.append((pdf_file, 'application/pdf'))

    try:
        msg = MIMEMultipart()
        msg['Subject'] = 'Website Vulnerability Report'
        msg['From'] = 'pundirved09@gmail.com'
        msg['To'] = recipient_email

        msg.attach(MIMEText(body, 'plain'))

        for attachment, mime_type in attachments:
            with open(attachment, "rb") as file_attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(file_attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment)}')
                part.add_header('Content-Type', mime_type)
                msg.attach(part)

        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        username = 'pundirved09@gmail.com'
        password = 'pnmaayexiejdikhr'  
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(username, password)
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
        print(f"{Fore.GREEN}Email sent successfully to {recipient_email} with attachments!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error sending email to {recipient_email}: {e}{Style.RESET_ALL}")


def discover_urls(url):
    
    discovered_urls = []
    visited = set()
    base_domain = url.split('//')[1].split('/')[0]
    
    try:
        discovered_urls.append(url)
        visited.add(url)
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            for anchor_tag in soup.find_all("a", href=True):
                href = anchor_tag["href"]
                if not href or href.startswith("#") or href.startswith("javascript:"):
                    continue
                    
                absolute_url = urljoin(url, href)
                
                if base_domain in absolute_url and absolute_url not in visited:
                    discovered_urls.append(absolute_url)
                    visited.add(absolute_url)
                    
                    if len(discovered_urls) >= 10:
                        print("Reached URL limit. Limiting scan to 10 URLs.")
                        break

        except requests.RequestException as e:
            print(f"Failed to fetch URLs from {url}: {e}")
    except Exception as e:
        print(f"Error discovering URLs: {e}")
        
    return discovered_urls


def scan_url(url):
    
    vulnerabilities = {}

    try:
        if is_sql_injection_vulnerable(url):
            vulnerabilities["SQL injection vulnerability"] = "Injecting SQL code into input fields"

        if is_xss_vulnerable(url):
            vulnerabilities["Cross-site scripting (XSS) vulnerability"] = "Injecting malicious scripts into input fields"

        if has_insecure_configuration(url):
            vulnerabilities["Insecure server configuration"] = "Exploiting insecure communication protocols"

        if is_open_redirect_vulnerable(url):
            vulnerabilities["Open Redirect vulnerability"] = "Exploiting redirection to malicious websites"

        if is_directory_traversal_vulnerable(url):
            vulnerabilities["Directory Traversal vulnerability"] = "Accessing restricted directories/files"

        check_security_headers(url, vulnerabilities)
    except Exception as e:
        print(f"Error scanning {url}: {e}")

    return vulnerabilities


def check_security_headers(url, vulnerabilities):
    
    try:
        response = requests.head(url, timeout=10)
        headers = response.headers

        if 'X-Frame-Options' not in headers:
            vulnerabilities["Missing X-Frame-Options Header"] = "Exposes the site to clickjacking attacks"

        if 'Content-Security-Policy' not in headers:
            vulnerabilities["Missing Content-Security-Policy Header"] = "Increases XSS risks"

        if 'Strict-Transport-Security' not in headers and url.startswith("https"):
            vulnerabilities["Missing Strict-Transport-Security Header"] = "Increases vulnerability to SSL stripping attacks"
    except requests.RequestException:
        pass


def is_sql_injection_vulnerable(url, session=None, debug=False):
    
    if session is None:
        session = requests.Session()
    
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))

    payloads = [
        "' OR '1'='1", "' OR 'a'='a", "';--", "' OR 1=1 --",
        "1; DROP TABLE users --", "' UNION SELECT NULL --", "') OR ('1'='1"
    ]
    error_patterns = [
        r"sql syntax error", r"mysql_fetch_\w+", r"ora-\d+",
        r"microsoft sql server.*error", r"unclosed quotation mark"
    ]

    for payload in payloads:
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            test_params = list(query_params.keys()) or ['id', 'q', 'search', 'user']
            for param in test_params:
                test_url = f"{url.split('?')[0]}?{param}={payload}"
                response = session.get(test_url, timeout=5)
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"{Fore.YELLOW}Possible SQL injection vulnerability detected with GET payload: {payload}{Style.RESET_ALL}")
                        return True

            try:
                response = session.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").lower()
                    form_url = urljoin(url, action)
                    fields = {}
                    for input_field in form.find_all("input"):
                        name = input_field.get("name")
                        if name and name.lower() in ['username', 'user', 'search', 'q', 'id']:
                            fields[name] = payload
                    if not fields:
                        continue
                    if method == "post":
                        response = session.post(form_url, data=fields, timeout=5)
                    else:
                        response = session.get(form_url, params=fields, timeout=5)
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            print(f"{Fore.YELLOW}Possible SQL injection vulnerability detected in form with payload: {payload}{Style.RESET_ALL}")
                            return True
            except (requests.RequestException, AttributeError) as e:
                if debug:
                    print(f"{Fore.YELLOW}Form test failed for {url}: {e}{Style.RESET_ALL}")
                continue

        except requests.RequestException as e:
            if debug:
                print(f"{Fore.YELLOW}GET test failed for {url}: {e}{Style.RESET_ALL}")
            continue

    return False


def is_xss_vulnerable(url, session=None, debug=False):
    
    if session is None:
        session = requests.Session()
    
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[408, 429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "\" onmouseover=\"alert('XSS')\"",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
    ]
    
    for payload in xss_payloads:
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            test_params = list(query_params.keys()) or ['input', 'q', 'search', 'name', 'query']
            for param in test_params:
                test_url = f"{url.split('?')[0]}?{param}={quote(payload)}"
                response = session.get(test_url, timeout=5)
                if payload.lower() in response.text.lower() or '<script>' in response.text.lower():
                    print(f"{Fore.YELLOW}Possible reflected XSS vulnerability detected with GET payload: {payload}{Style.RESET_ALL}")
                    return True
                if 'innerHTML' in response.text.lower() or 'eval(' in response.text.lower():
                    print(f"{Fore.YELLOW}Possible DOM-based XSS vulnerability detected with GET payload: {payload}{Style.RESET_ALL}")
                    return True

            try:
                response = session.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").lower()
                    form_url = urljoin(url, action)
                    fields = {}
                    for input_field in form.find_all("input"):
                        name = input_field.get("name")
                        if name and name.lower() in ['search', 'q', 'name', 'query']:
                            fields[name] = payload
                    if not fields:
                        continue
                    if method == "post":
                        response = session.post(form_url, data=fields, timeout=5)
                    else:
                        response = session.get(form_url, params=fields, timeout=5)
                    if payload.lower() in response.text.lower() or '<script>' in response.text.lower():
                        print(f"{Fore.YELLOW}Possible reflected XSS vulnerability detected in form with payload: {payload}{Style.RESET_ALL}")
                        return True
            except (requests.RequestException, AttributeError) as e:
                if debug:
                    print(f"{Fore.YELLOW}Form test failed for {url}: {e}{Style.RESET_ALL}")
                continue

        except requests.RequestException as e:
            if debug:
                print(f"{Fore.YELLOW}GET test failed for {url}: {e}{Style.RESET_ALL}")
            continue

    return False

def has_insecure_configuration(url, session=None, debug=False):
    
    if session is None:
        session = requests.Session()
    
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[408, 429, 500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))

    if not url.startswith(("http://", "https://")):
        url = urljoin("https://", url)
    
    try:
        response = session.head(url, timeout=5)
        if response.url.startswith("http://"):
            print(f"{Fore.YELLOW}Insecure server configuration detected: {url} uses HTTP instead of HTTPS{Style.RESET_ALL}")
            return True
        if 'strict-transport-security' not in response.headers:
            print(f"{Fore.YELLOW}Missing HSTS header detected: {url}{Style.RESET_ALL}")
            return True
    except requests.RequestException as e:
        if debug:
            print(f"{Fore.YELLOW}Head request failed for {url}: {e}{Style.RESET_ALL}")
        return False

    return False


def is_open_redirect_vulnerable(url):
    
    redirect_payloads = [
        "//evil.com",
        "https://evil.com",
        "//google.com",
        "https://google.com",
    ]
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        
        redirect_params = ["redirect", "url", "next", "goto", "return", "returnUrl", "returnTo", "destination"]
        
        for link in soup.find_all("a", href=True):
            href = link["href"]
            
            for param in redirect_params:
                if f"{param}=" in href:
                    for payload in redirect_payloads:
                        test_url = f"{urljoin(url, href.split(param+'=')[0])}{param}={payload}"
                        try:
                            response = requests.get(test_url, allow_redirects=False, timeout=10)
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get("Location", "")
                                if any(p.replace("//", "") in location for p in redirect_payloads):
                                    print(f"Possible Open Redirect vulnerability detected with payload: {payload}")
                                    return True
                        except requests.RequestException:
                            continue
    except:
        pass
        
    for payload in redirect_payloads:
        for param in ["redirect", "url", "next", "goto", "return"]:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, allow_redirects=False, timeout=10)
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get("Location", "")
                    if any(p.replace("//", "") in location for p in redirect_payloads):
                        print(f"Possible Open Redirect vulnerability detected with payload: {payload}")
                        return True
            except requests.RequestException:
                continue
                
    return False


def is_directory_traversal_vulnerable(url):
    
    traversal_payloads = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",

    # Encoded forward slashes (%2f)
    "..%2fetc%2fpasswd",
    "..%2f..%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",

    # Double-encoded slashes
    "..%252f..%252f..%252fetc%252fpasswd",

    # Windows paths
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "c:\\windows\\win.ini",

    # Null byte injection (legacy PHP apps)
    "../../../etc/passwd%00",
    "..%2f..%2f..%2fetc%2fpasswd%00",

    # Alternative traversal patterns
    "..././..././.../etc/passwd",
    "..;/..;/..;/etc/passwd",  # Some poorly sanitized servers

    # Unix device files (for deeper exploitation testing)
    "/dev/null",
    "/dev/random",
    "/proc/self/environ",

    # Windows system32 access
    "../../boot.ini",
    "..\\..\\boot.ini"
]

    
    file_params = ["file", "path", "folder", "directory", "dir", "include", "page", "doc", "document"]
    
    for param in file_params:
        for payload in traversal_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=10)
                content = response.text.lower()
                
                if ("root:" in content and ":/bin/bash" in content) or \
                   ("for 16-bit app support" in content) or \
                   ("[extensions]" in content):
                    print(f"Possible Directory Traversal vulnerability detected with payload: {payload}")
                    return True
            except requests.RequestException:
                continue
    
    return False



def main():
    init(autoreset=True)
    
    output_dir = "scan_results"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"vulnerability_scan_{timestamp}.txt")
    
    with capture_output(output_file):
        print(f"{Fore.CYAN}Vulnerability Scan Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print("-" * 80)
        
        recipient_email = input("Please enter the recipient's email address for the report: ").strip()
        if not recipient_email:
            print(f"{Fore.RED}No email provided. Email report will not be sent.{Style.RESET_ALL}")
        
        if len(sys.argv) > 2:
            api_key = sys.argv[2]
        else:
            api_key = os.environ.get("NVD_API_KEY", "YOUR_API_KEY_HERE")
        
        if len(sys.argv) > 1:
            target_url = sys.argv[1]
        else:
            target_url = "http://testphp.vulnweb.com"
            
        print(f"Target URL: {target_url}")
        print(f"Using NVD API key: {'*' * len(api_key)}")
        print(f"Recipient Email: {recipient_email}")
        
        try:
            scan_website(target_url, api_key, recipient_email)
        except Exception as e:
            print(f"\n{Fore.RED}Error during scan: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()

    
        
        print("-" * 80)
        print(f"{Fore.CYAN}Scan Completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"Full scan results have been saved to: {output_file}")

        open_dashboard()
        
       


if __name__ == "__main__":

    main()
    
