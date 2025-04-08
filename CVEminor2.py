import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import webbrowser
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
import threading
import webbrowser
from flask import Flask, render_template, jsonify
import mysql.connector
from datetime import datetime
from datetime import datetime
from tabulate import tabulate
import mysql.connector
from mysql.connector import Error
from colorama import Fore, Style

@dataclass
class CVEDetails:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: str
    references: List[str]


class NVDApiClient:
    def _init_(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            "apiKey": api_key
        }
        # Rate limiting to avoid API throttling
        self.request_delay = 6  # seconds between requests

    def get_cve_details(self, keyword: str, max_results: int = 5) -> List[CVEDetails]:
        """
        Query the NVD API for CVEs related to a specific keyword.
        
        Args:
            keyword: Search term for vulnerabilities
            max_results: Maximum number of results to return
            
        Returns:
            List of CVEDetails objects
        """
        try:
            # Fixed the API endpoint - don't append CVE to the URL
            # Using the keywordSearch parameter correctly
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results
            }
            
            # Add delay to avoid rate limiting
            time.sleep(self.request_delay)
            
            response = requests.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            # Check for rate limiting or other errors
            if response.status_code == 403:
                print(f"API rate limit exceeded or authentication error: {response.text}")
                return []
                
            response.raise_for_status()
            data = response.json()
            
            # Debug information - optional
            print(f"Found {len(data.get('vulnerabilities', []))} CVEs matching '{keyword}'")
            
            cve_list = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                
                # Handle both CVSS v3.1 and v3.0 metrics
                cvss_score = 0.0
                severity = "UNKNOWN"
                
                # Try CVSS 3.1 first
                if cve.get("metrics", {}).get("cvssMetricV31"):
                    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                    cvss_data = metrics.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                # Fall back to CVSS 3.0
                elif cve.get("metrics", {}).get("cvssMetricV30"):
                    metrics = cve.get("metrics", {}).get("cvssMetricV30", [{}])[0]
                    cvss_data = metrics.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                # Fall back to CVSS 2.0
                elif cve.get("metrics", {}).get("cvssMetricV2"):
                    metrics = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0]
                    cvss_data = metrics.get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    # Map CVSS 2.0 score to severity
                    if cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                
                # Get the English description when available
                description = "No description available"
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "No description available")
                        break
                
                # Create CVE details object
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
    """Get relevant CVEs for a specific vulnerability type."""
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
    def _init_(self, filename):
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


def scan_website(url, api_key: str):
    """
    Discover URLs and scan each for potential vulnerabilities, including CVE details.
    """
    try:
        # Initialize NVD API client with rate limiting
        nvd_client = NVDApiClient(api_key)
        
        # Discover URLs from the target website
        print(f"Discovering URLs on {url}...")
        discovered_urls = discover_urls(url)
        print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")
        for i, discovered_url in enumerate(discovered_urls, start=1):
            print(f"{i}. {discovered_url}")

        vulnerabilities_summary = []

        # Scan each discovered URL for vulnerabilities
        for page_url in discovered_urls:
            print(f"\nScanning {page_url}...")
            vulnerabilities = scan_url(page_url)
            
            if vulnerabilities:
                print(f"\n{Fore.RED}Vulnerabilities found on {page_url}:{Style.RESET_ALL}")
                
                for vulnerability, attack_method in vulnerabilities.items():
                    print(f"\n{Fore.YELLOW}Vulnerability: {vulnerability}{Style.RESET_ALL}")
                    print(f"Attack Method: {attack_method}")
                    
                    # Get and display CVE details
                    cve_details = get_vulnerability_cves(vulnerability, nvd_client)
                    
                    if cve_details:
                        print(f"\n{Fore.CYAN}Related CVEs:{Style.RESET_ALL}")
                        for cve in cve_details:
                            # Color-code severity
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

                    # Add to summary with extended CVE information.
                    # Ensure that each entry has nine elements corresponding to:
                    # "Page URL", "Vulnerability", "Attack Method", "CVE ID",
                    # "Severity", "CVSS Score", "Published Date", "Description", "References"
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

        # Generate reports if vulnerabilities were found
        if vulnerabilities_summary:
            save_vulnerabilities_to_document(vulnerabilities_summary)
            generate_pdf_report(vulnerabilities_summary)
            send_email_report(vulnerabilities_summary)
            save_vulnerabilities_to_json(vulnerabilities_summary)  # Add this line
        else:
            print(f"\n{Fore.GREEN}No vulnerabilities found on any of the URLs.{Style.RESET_ALL}")

    except Exception as e:
        print(f"\n{Fore.RED}An error occurred while scanning the website: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


def save_vulnerabilities_to_document(vulnerabilities_summary):
    """
    Save the vulnerabilities summary to a text document as a table,
    including extended CVE details: Published Date, Description, and References.
    Also save to MySQL database (not implemented here).
    """
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
    # Save to MySQL database as well

# Add this function to your existing code


def save_vulnerabilities_to_json(vulnerabilities_summary):
    """
    Save the vulnerabilities summary to a JSON file for the dashboard.
    """
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
    """
    Generate a PDF report of the vulnerabilities found.
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Website Vulnerability Report', 0, 1, 'C')
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        pdf.ln(10)

        # Add table headers
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(60, 10, 'Vulnerability', 1, 0, 'C')
        pdf.cell(60, 10, 'CVE ID', 1, 0, 'C')
        pdf.cell(30, 10, 'Severity', 1, 0, 'C')
        pdf.cell(30, 10, 'CVSS Score', 1, 1, 'C')

        # Add table data
        pdf.set_font('Arial', '', 10)
        for row in vulnerabilities_summary:
            # Print URL as a section header
            pdf.ln(5)
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 10, f"URL: {row[0]}", 0, 1)
            pdf.set_font('Arial', '', 10)
            
            # Print vulnerability details
            pdf.cell(60, 10, row[1], 1, 0)
            pdf.cell(60, 10, row[3], 1, 0)
            pdf.cell(30, 10, row[4], 1, 0)
            pdf.cell(30, 10, row[5], 1, 1)
            
            # Print attack method
            pdf.cell(0, 10, f"Attack Method: {row[2]}", 0, 1)
            pdf.ln(5)

        pdf.output("vulnerability_report.pdf")
        print(f"{Fore.GREEN}PDF report generated: vulnerability_report.pdf{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error generating PDF report: {e}{Style.RESET_ALL}")


def send_email_report(vulnerabilities_summary):
    """
    Send an email report with vulnerability findings.
    """
    if not vulnerabilities_summary:
        print("No vulnerabilities to report.")
        return

    # Create the email body
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

    # Create the text file to attach
    file_name = "vulnerabilities_summary.txt"
    
    # Try to attach PDF if it exists
    pdf_file = "vulnerability_report.pdf"
    attachments = []
    if os.path.exists(file_name):
        attachments.append((file_name, 'text/plain'))
    if os.path.exists(pdf_file):
        attachments.append((pdf_file, 'application/pdf'))

    try:
        # Create the email message
        msg = MIMEMultipart()
        msg['Subject'] = 'Website Vulnerability Report'
        msg['From'] = 'pundirved09@gmail.com'
        msg['To'] = 'vedanshpundir43@gmail.com'

        # Attach the body text
        msg.attach(MIMEText(body, 'plain'))

        # Attach files
        for attachment, mime_type in attachments:
            with open(attachment, "rb") as file_attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(file_attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment)}')
                part.add_header('Content-Type', mime_type)
                msg.attach(part)

        # Email server details
        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        username = 'pundirved09@gmail.com'
        password = 'deba xgmj fquj urwm'  # Consider using environment variables for passwords

        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(username, password)
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
        print(f"{Fore.GREEN}Email sent successfully with attachments!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error sending email: {e}{Style.RESET_ALL}")


def discover_urls(url):
    """
    Discover all URLs on the given website.
    """
    discovered_urls = []
    visited = set()
    base_domain = url.split('//')[1].split('/')[0]
    
    try:
        # Add the base URL
        discovered_urls.append(url)
        visited.add(url)
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            # Extract and resolve all anchor tags
            for anchor_tag in soup.find_all("a", href=True):
                href = anchor_tag["href"]
                if not href or href.startswith("#") or href.startswith("javascript:"):
                    continue
                    
                absolute_url = urljoin(url, href)
                
                # Only include URLs from the same domain and not already visited
                if base_domain in absolute_url and absolute_url not in visited:
                    discovered_urls.append(absolute_url)
                    visited.add(absolute_url)
                    
                    # Limit the number of URLs to scan
                    if len(discovered_urls) >= 10:
                        print("Reached URL limit. Limiting scan to 10 URLs.")
                        break

        except requests.RequestException as e:
            print(f"Failed to fetch URLs from {url}: {e}")
    except Exception as e:
        print(f"Error discovering URLs: {e}")
        
    return discovered_urls


def scan_url(url):
    """
    Scan a URL for common vulnerabilities.
    """
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
    """
    Check for missing HTTP security headers.
    """
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
        # If we can't connect, don't add header vulnerabilities
        pass


def is_sql_injection_vulnerable(url):
    """
    Check for SQL injection vulnerabilities.
    """
    payloads = ["' OR '1'='1", "' OR 'a'='a", "';--", "' OR 1=1 --"]
    
    for payload in payloads:
        try:
            # Try both GET and POST methods
            # GET method
            response = requests.get(f"{url}?id={payload}", timeout=10)
            if re.search(r"sql|database|error|syntax|mysql|oracle|microsoft|server", response.text, re.IGNORECASE):
                print(f"Possible SQL injection vulnerability detected with GET payload: {payload}")
                return True
                
            # Try POST method on forms
            try:
                response = requests.get(url, timeout=10)
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Find forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").lower()
                    form_url = urljoin(url, action)
                    
                    # Get form fields
                    fields = {}
                    for input_field in form.find_all("input"):
                        name = input_field.get("name")
                        if name:
                            fields[name] = payload
                    
                    # Submit form with payload
                    if method == "post":
                        response = requests.post(form_url, data=fields, timeout=10)
                    else:
                        response = requests.get(form_url, params=fields, timeout=10)
                        
                    if re.search(r"sql|database|error|syntax|mysql|oracle|microsoft|server", response.text, re.IGNORECASE):
                        print(f"Possible SQL injection vulnerability detected in form with payload: {payload}")
                        return True
            except:
                # Skip form testing if it fails
                pass
                
        except requests.RequestException:
            continue
            
    return False


def is_xss_vulnerable(url):
    """
    Check for XSS vulnerabilities.
    """
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "\" onmouseover=\"alert('XSS')\"",
        "<img src=x onerror=alert('XSS')>",
    ]
    
    for payload in xss_payloads:
        try:
            # Test GET parameters
            response = requests.get(f"{url}?input={payload}", timeout=10)
            if payload in response.text:
                print(f"Possible XSS vulnerability detected with payload: {payload}")
                return True
                
            # Test forms
            try:
                response = requests.get(url, timeout=10)
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Find forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").lower()
                    form_url = urljoin(url, action)
                    
                    # Get form fields
                    fields = {}
                    for input_field in form.find_all("input"):
                        name = input_field.get("name")
                        if name:
                            fields[name] = payload
                    
                    # Submit form with payload
                    if method == "post":
                        response = requests.post(form_url, data=fields, timeout=10)
                    else:
                        response = requests.get(form_url, params=fields, timeout=10)
                        
                    if payload in response.text:
                        print(f"Possible XSS vulnerability detected in form with payload: {payload}")
                        return True
            except:
                # Skip form testing if it fails
                pass
                
        except requests.RequestException:
            continue
            
    return False


def has_insecure_configuration(url):
    """
    Check for insecure server configurations (e.g., using HTTP instead of HTTPS).
    """
    if not url.startswith("https"):
        print(f"Insecure server configuration detected: {url} uses HTTP instead of HTTPS")
        return True
    return False


def is_open_redirect_vulnerable(url):
    """
    Check for Open Redirect vulnerabilities.
    """
    redirect_payloads = [
        "//evil.com",
        "https://evil.com",
        "//google.com",
        "https://google.com",
    ]
    
    # Find potential redirect parameters
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Look for common redirect parameter names in links
        redirect_params = ["redirect", "url", "next", "goto", "return", "returnUrl", "returnTo", "destination"]
        
        for link in soup.find_all("a", href=True):
            href = link["href"]
            
            # Test if any redirect parameters exist in the link
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
        
    # Try direct parameter injection
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
    """
    Check for Directory Traversal vulnerabilities.
    """
    traversal_payloads = [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "../../../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini"
    ]
    
    # Common file parameters
    file_params = ["file", "path", "folder", "directory", "dir", "include", "page", "doc", "document"]
    
    # Try each parameter with each payload
    for param in file_params:
        for payload in traversal_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=10)
                content = response.text.lower()
                
                # Check for common file contents
                if ("root:" in content and ":/bin/bash" in content) or \
                   ("for 16-bit app support" in content) or \
                   ("[extensions]" in content):
                    print(f"Possible Directory Traversal vulnerability detected with payload: {payload}")
                    return True
            except requests.RequestException:
                continue
    
    return False


def main():
    """Main function to run the vulnerability scanner"""
    # Initialize colorama for colored output
    init(autoreset=True)
    
    # Create output directory if it doesn't exist
    output_dir = "scan_results"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"vulnerability_scan_{timestamp}.txt")
    
    # Capture all output
    with capture_output(output_file):
        print(f"{Fore.CYAN}Vulnerability Scan Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print("-" * 80)
        
        # Get API key from environment variable or use default
        if len(sys.argv) > 2:
            api_key = sys.argv[2]
        else:
            api_key = os.environ.get("NVD_API_KEY", "YOUR_API_KEY_HERE")

        
        # Get target URL from command line or use default
        if len(sys.argv) > 1:
            target_url = sys.argv[1]
        else:
            target_url = "http://testphp.vulnweb.com"
            
        print(f"Target URL: {target_url}")
        print(f"Using NVD API key: {'*' * len(api_key)}")
        
        # Run the scan
        try:
            scan_website(target_url, api_key)
        except Exception as e:
            print(f"\n{Fore.RED}Error during scan: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
        
        print("-" * 80)
        print(f"{Fore.CYAN}Scan Completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"Full scan results have been saved to: {output_file}")

        


if __name__ == "_main_":
    main()
    if len(sys.argv) != 3:
        print("Usage: python newcode.py <URL> <API_KEY>")
    else:
        scan_website(sys.argv[1], sys.argv[2])
