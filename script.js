// Charts will be stored here to destroy when re-rendering
let charts = {
    severityChart: null,
    cvssChart: null,
    vulnTypeChart: null,
    urlChart: null
  };
  // OWASP Top 10 Vulnerability Classifications and Descriptions
  const owaspVulnerabilityMap = {
    "SQL injection vulnerability": {
      category: "A03:2021",
      name: "Injection",
      description: "SQL injection allows attackers to inject malicious SQL statements that can manipulate the database, potentially leading to unauthorized access, data theft, deletion, or modification."
    },
    "Cross-site scripting (XSS) vulnerability": {
      category: "A03:2021",
      name: "Injection",
      description: "XSS allows attackers to inject client-side scripts into web pages viewed by others, bypassing same-origin policy and potentially stealing session tokens or cookies."
    },
    "Missing X-Frame-Options Header": {
      category: "A05:2021",
      name: "Security Misconfiguration",
      description: "Absence of X-Frame-Options header allows attackers to embed your site in a frame, potentially enabling clickjacking attacks where users can be tricked into clicking on disguised elements."
    },
    "Directory Traversal vulnerability": {
      category: "A01:2021",
      name: "Broken Access Control",
      description: "Directory traversal allows attackers to access files and directories outside the intended web document root, potentially exposing sensitive configuration files or system files."
    },
    "Insecure server configuration": {
      category: "A05:2021",
      name: "Security Misconfiguration",
      description: "Insecure server configuration, such as default settings, unnecessary services, or improper access controls, can expose vulnerabilities that attackers can exploit to compromise the system."
    },
    "Cross-Site Request Forgery (CSRF)": {
      category: "A01:2021",
      name: "Broken Access Control",
      description: "CSRF forces authenticated users to submit unwanted requests, potentially causing state-changing actions like fund transfers or password changes without user consent."
    },
    "Insecure Direct Object Reference": {
      category: "A01:2021",
      name: "Broken Access Control",
      description: "IDOR occurs when an application provides direct access to objects based on user-supplied input, allowing attackers to bypass authorization and access resources directly."
    },
    "Server-Side Request Forgery": {
      category: "A10:2021",
      name: "Server-Side Request Forgery",
      description: "SSRF allows attackers to induce the server to make HTTP requests to arbitrary domains of the attacker's choosing, potentially allowing access to internal services behind firewalls."
    },
    "XML External Entity (XXE)": {
      category: "A03:2021",
      name: "Injection",
      description: "XXE attacks target applications that parse XML input, potentially allowing disclosure of confidential data, server-side request forgery, port scanning, or remote code execution."
    },
    "Open Redirect": {
      category: "A01:2021",
      name: "Broken Access Control",
      description: "Open redirect vulnerabilities occur when a web application accepts untrusted input that could cause it to redirect users to malicious sites, facilitating phishing attacks."
    },
    "Insecure Deserialization": {
      category: "A08:2021",
      name: "Software and Data Integrity Failures",
      description: "Insecure deserialization can enable an attacker to execute arbitrary code, manipulate application logic, or access unauthorized data when untrusted data is processed."
    },
    "Broken Authentication": {
      category: "A07:2021",
      name: "Identification and Authentication Failures",
      description: "Authentication flaws allow attackers to compromise passwords, keys, session tokens, or exploit implementation flaws to assume users' identities temporarily or permanently."
    }}
  // Sample vulnerability data
  const sampleVulnerabilityData = [
    { id: 1, url: "http://testphp.vulnweb.com/page1", vulnerability: "SQL injection vulnerability", attackMethod: "Injecting SQL code", cveId: "CVE-2023-1234", severity: "HIGH", cvssScore: 8.5 },
    { id: 2, url: "http://testphp.vulnweb.com/page1", vulnerability: "Cross-site scripting (XSS) vulnerability", attackMethod: "Injecting scripts", cveId: "CVE-2022-5678", severity: "MEDIUM", cvssScore: 6.2 },
    { id: 3, url: "http://testphp.vulnweb.com/page2", vulnerability: "Missing X-Frame-Options Header", attackMethod: "Clickjacking", cveId: "CVE-2022-9012", severity: "LOW", cvssScore: 3.4 },
    { id: 4, url: "http://testphp.vulnweb.com/page3", vulnerability: "Directory Traversal vulnerability", attackMethod: "Path manipulation", cveId: "CVE-2023-4321", severity: "HIGH", cvssScore: 9.1 },
    { id: 5, url: "http://testphp.vulnweb.com/page3", vulnerability: "Insecure server configuration", attackMethod: "Exploiting configs", cveId: "CVE-2022-8765", severity: "MEDIUM", cvssScore: 5.8 }
  ];
  
  // Tab functionality
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab');
      
      // Update button state
      tabButtons.forEach(btn => btn.classList.remove('active'));
      button.classList.add('active');
      
      // Update content visibility
      tabContents.forEach(content => content.classList.remove('active'));
      document.getElementById(tabName).classList.add('active');
    });
  });
  
  // Initialize dashboard
  function initDashboard(data) {
    updateStats(data);
    renderDetailTable(data);
    renderSeverityPieChart(data);
    renderCVSSBarChart(data);
    renderVulnTypeChart(data);
    renderURLChart(data);
  }
  
  // Reset all charts
  function resetCharts() {
    Object.values(charts).forEach(chart => {
      if (chart) {
        chart.destroy();
      }
    });
  }
  
  // Update dashboard statistics
  function updateStats(data) {
    const severityCounts = {
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };
    
    // Count occurrences of each severity
    data.forEach(item => {
      if (item && item.severity) {
        severityCounts[item.severity] = (severityCounts[item.severity] || 0) + 1;
      }
    });
    
    document.getElementById('total-count').textContent = data.length;
    document.getElementById('high-count').textContent = severityCounts.HIGH || 0;
    document.getElementById('medium-count').textContent = severityCounts.MEDIUM || 0;
    document.getElementById('low-count').textContent = severityCounts.LOW || 0;
  }
  
  // Render detail table
  function renderDetailTable(data) {
    const tableBody = document.querySelector('#vuln-table tbody');
    tableBody.innerHTML = '';
    
    data.forEach(item => {
      const row = document.createElement('tr');
      
      row.innerHTML = `
        <td>${item.url}</td>
        <td>${item.vulnerability}</td>
        <td>${item.attackMethod || 'N/A'}</td>
        <td>${item.cveId}</td>
        <td>
          <span class="severity-badge severity-${item.severity.toLowerCase()}">
            ${item.severity}
          </span>
        </td>
        <td>${item.cvssScore.toFixed(1)}</td>
      `;
      
      tableBody.appendChild(row);
    });
  }
  
  // Render severity pie chart
  function renderSeverityPieChart(data) {
    const severityCounts = {
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };
    
    // Count occurrences of each severity
    data.forEach(item => {
      if (item && item.severity) {
        severityCounts[item.severity] = (severityCounts[item.severity] || 0) + 1;
      }
    });
    
    const pieData = {
      labels: ['High', 'Medium', 'Low'],
      datasets: [{
        data: [
          severityCounts.HIGH || 0,
          severityCounts.MEDIUM || 0,
          severityCounts.LOW || 0
        ],
        backgroundColor: [
          '#ff4d4f',
          '#faad14',
          '#52c41a'
        ]
      }]
    };
    
    const ctx = document.getElementById('severity-chart').getContext('2d');
    
    if (charts.severityChart) {
      charts.severityChart.destroy();
    }
    
    charts.severityChart = new Chart(ctx, {
      type: 'pie',
      data: pieData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom'
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const value = context.raw;
                const percentage = Math.round((value / data.length) * 100);
                return `${context.label}: ${value} (${percentage}%)`;
              }
            }
          }
        }
      }
    });
  }
  
  // Render CVSS score bar chart
  function renderCVSSBarChart(data) {
    // Sort data by CVSS score for better visualization
    const sortedData = [...data].sort((a, b) => b.cvssScore - a.cvssScore);
    
    const labels = sortedData.map((item, index) => `Vuln ${index + 1}`);
    const values = sortedData.map(item => item.cvssScore);
    const colors = sortedData.map(item => {
      if (item.cvssScore >= 7) return '#ff4d4f';
      if (item.cvssScore >= 4) return '#faad14';
      return '#52c41a';
    });
    
    const ctx = document.getElementById('cvss-chart').getContext('2d');
    
    if (charts.cvssChart) {
      charts.cvssChart.destroy();
    }
    
    charts.cvssChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'CVSS Score',
          data: values,
          backgroundColor: colors,
          barThickness: 20
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            max: 10,
            title: {
              display: true,
              text: 'CVSS Score'
            }
          },
          x: {
            title: {
              display: true,
              text: 'Vulnerability'
            }
          }
        },
        plugins: {
          tooltip: {
            callbacks: {
              title: function(tooltipItems) {
                const index = tooltipItems[0].dataIndex;
                return sortedData[index].vulnerability;
              },
              afterTitle: function(tooltipItems) {
                const index = tooltipItems[0].dataIndex;
                return sortedData[index].url;
              }
            }
          }
        }
      }
    });
  }
  
  // Render vulnerability type chart
  function renderVulnTypeChart(data) {
    // Group vulnerabilities by type
    const vulnTypes = {};
    
    data.forEach(item => {
      if (!item || !item.vulnerability) return;
      
      if (!vulnTypes[item.vulnerability]) {
        vulnTypes[item.vulnerability] = {
          count: 1,
          avgCVSS: item.cvssScore || 0
        };
      } else {
        vulnTypes[item.vulnerability].count++;
        const prevTotal = vulnTypes[item.vulnerability].avgCVSS * (vulnTypes[item.vulnerability].count - 1);
        const newScore = item.cvssScore || 0;
        vulnTypes[item.vulnerability].avgCVSS = (prevTotal + newScore) / vulnTypes[item.vulnerability].count;
      }
    });
    
    // Sort by count for better visualization
    const sortedTypes = Object.entries(vulnTypes)
      .sort((a, b) => b[1].count - a[1].count)
      .reduce((obj, [key, value]) => {
        obj[key] = value;
        return obj;
      }, {});
    
    const labels = Object.keys(sortedTypes).map(type => {
      // Get first two words for display
      const words = type.split(' ');
      return words.slice(0, 2).join(' ');
    });
    
    const countData = Object.values(sortedTypes).map(type => type.count);
    const cvssData = Object.values(sortedTypes).map(type => parseFloat(type.avgCVSS.toFixed(1)));
    
    const ctx = document.getElementById('vuln-type-chart').getContext('2d');
    
    if (charts.vulnTypeChart) {
      charts.vulnTypeChart.destroy();
    }
    
    charts.vulnTypeChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Occurrences',
            data: countData,
            backgroundColor: '#8884d8',
            yAxisID: 'y'
          },
          {
            label: 'Avg CVSS Score',
            data: cvssData,
            backgroundColor: '#82ca9d',
            type: 'line',
            yAxisID: 'y1'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            position: 'left',
            title: {
              display: true,
              text: 'Count'
            }
          },
          y1: {
            beginAtZero: true,
            position: 'right',
            max: 10,
            grid: {
              drawOnChartArea: false
            },
            title: {
              display: true,
              text: 'CVSS Score'
            }
          }
        },
        plugins: {
          tooltip: {
            callbacks: {
              title: function(tooltipItems) {
                const index = tooltipItems[0].dataIndex;
                return Object.keys(sortedTypes)[index];
              }
            }
          }
        }
      }
    });
  }
  
  // Render URL chart
  function renderURLChart(data) {
    // URL-based vulnerability count
    const urls = {};
    
    data.forEach(item => {
      if (!item || !item.url) return;
      
      let displayPath = item.url;
      try {
        const urlObj = new URL(item.url);
        displayPath = urlObj.pathname || item.url;
        if (displayPath === "/") {
          displayPath = urlObj.hostname;
        }
      } catch (e) {
        // URL parsing failed, keep the original URL
        console.log("URL parsing failed for:", item.url);
      }
      
      if (!urls[item.url]) {
        urls[item.url] = {
          name: displayPath,
          count: 1,
          high: item.severity === 'HIGH' ? 1 : 0,
          medium: item.severity === 'MEDIUM' ? 1 : 0,
          low: item.severity === 'LOW' ? 1 : 0
        };
      } else {
        urls[item.url].count++;
        if (item.severity === 'HIGH') urls[item.url].high++;
        else if (item.severity === 'MEDIUM') urls[item.url].medium++;
        else if (item.severity === 'LOW') urls[item.url].low++;
      }
    });
    
    const labels = Object.values(urls).map(url => url.name);
    const highCounts = Object.values(urls).map(url => url.high);
    const mediumCounts = Object.values(urls).map(url => url.medium);
    const lowCounts = Object.values(urls).map(url => url.low);
    
    const ctx = document.getElementById('url-chart').getContext('2d');
    
    if (charts.urlChart) {
      charts.urlChart.destroy();
    }
    
    charts.urlChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'High Severity',
            data: highCounts,
            backgroundColor: '#ff4d4f',
            stack: 'Stack 0'
          },
          {
            label: 'Medium Severity',
            data: mediumCounts,
            backgroundColor: '#faad14',
            stack: 'Stack 0'
          },
          {
            label: 'Low Severity',
            data: lowCounts,
            backgroundColor: '#52c41a',
            stack: 'Stack 0'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            stacked: true,
            title: {
              display: true,
              text: 'Count'
            }
          },
          x: {
            stacked: true
          }
        },
        plugins: {
          tooltip: {
            callbacks: {
              title: function(tooltipItems) {
                const index = tooltipItems[0].dataIndex;
                const url = Object.keys(urls)[index];
                return url;
              }
            }
          }
        }
      }
    });
  }
  
  // Function to parse the vulnerability scan text report
  function parseVulnerabilityScanReport(text) {
    let scanDate = null;
    const vulnerabilities = [];
    let idCounter = 1;
    
    // Extract scan date
    const scanDateMatch = text.match(/Scan Date: ([^\n]+)/);
    if (scanDateMatch && scanDateMatch[1]) {
      scanDate = scanDateMatch[1].trim();
    }
    
    // Find the table section
    const lines = text.split('\n');
    let tableStartIndex = -1;
    let headerLineIndex = -1;
    
    // Find the table header line
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('| Page URL') && lines[i].includes('| Vulnerability') && lines[i].includes('| CVE ID')) {
        headerLineIndex = i;
        break;
      }
    }
    
    if (headerLineIndex === -1) {
      return { scanDate, vulnerabilities: [] };
    }
    
    // Get the header columns
    const headerLine = lines[headerLineIndex];
    const headerColumns = headerLine.split('|').map(col => col.trim()).filter(col => col);
    
    // Find the separator line
    let separatorLineIndex = -1;
    for (let i = headerLineIndex + 1; i < lines.length; i++) {
      if (lines[i].includes('+=') && lines[i].includes('=+')) {
        separatorLineIndex = i;
        break;
      }
    }
    
    if (separatorLineIndex === -1) {
      return { scanDate, vulnerabilities: [] };
    }
    
    // Process table rows
    for (let i = separatorLineIndex + 1; i < lines.length; i++) {
      const line = lines[i];
      // Check if this is a data row (contains pipe characters with content between them)
      if (line.includes('|') && !line.includes('+=') && !line.includes('=+')) {
        // Split by | and clean up each cell
        const columns = line.split('|').map(col => col.trim()).filter(col => col);
        
        if (columns.length >= 5) { // Ensure we have enough columns
          const vulnerability = {
            id: idCounter++,
            url: columns[0],
            vulnerability: columns[1],
            attackMethod: columns[2],
            cveId: columns[3],
            severity: columns[4],
            cvssScore: parseFloat(columns[5] || '0')
          };
          
          vulnerabilities.push(vulnerability);
        }
      }
    }
    
    return { scanDate, vulnerabilities };
  }
  
  // File upload handler
  document.getElementById('file-upload-input').addEventListener('change', event => {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    
    reader.onload = e => {
      try {
        const fileContent = e.target.result;
        const { scanDate, vulnerabilities } = parseVulnerabilityScanReport(fileContent);
        
        // Update scan info
        if (scanDate) {
          document.getElementById('scan-date').textContent = `Scan Date: ${scanDate}`;
          document.getElementById('scan-info').style.display = 'block';
        } else {
          document.getElementById('scan-info').style.display = 'none';
        }
        
        // Reset charts
        resetCharts();
        
        // Update dashboard with new data
        if (vulnerabilities.length > 0) {
          initDashboard(vulnerabilities);
        } else {
          alert("No vulnerability data could be extracted from the file. Please check the format.");
        }
      } catch (error) {
        console.error("Error parsing file:", error);
        alert("Error parsing file: " + (error.message || "Unknown error"));
      }
    };
    
    reader.onerror = () => {
      alert("Error reading file. Please try again.");
    };
    
    reader.readAsText(file);
  });
  
  // Initialize dashboard with sample data
  document.addEventListener('DOMContentLoaded', () => {
    initDashboard(sampleVulnerabilityData);
  });

  /* JavaScript for OWASP Accordion */
document.addEventListener("DOMContentLoaded", function () {
    const accordionItems = document.querySelectorAll(".accordion-item");
    
    accordionItems.forEach((item) => {
      const header = item.querySelector(".accordion-header");
      header.addEventListener("click", function () {
        item.classList.toggle("active");
      });
    });
  
    const badges = document.querySelectorAll(".owasp-badge");
    badges.forEach((badge) => {
      badge.addEventListener("click", function () {
        const category = this.getAttribute("data-category");
        accordionItems.forEach((item) => {
          if (item.getAttribute("data-category") === category) {
            item.classList.add("active");
            item.scrollIntoView({ behavior: "smooth" });
          }
        });
      });
    });
  });

  document.addEventListener("DOMContentLoaded", function () {
    const tabs = document.querySelectorAll(".tab-button");
    const contents = document.querySelectorAll(".tab-content");
    
    tabs.forEach(tab => {
        tab.addEventListener("click", function () {
            const target = this.getAttribute("data-tab");
            
            contents.forEach(content => {
                content.classList.remove("active");
            });
            
            tabs.forEach(t => t.classList.remove("active"));
            this.classList.add("active");
            document.getElementById(target).classList.add("active");
        });
    });

    // Fix: Ensure the OWASP tab can be selected
    const owaspTabButton = document.createElement("button");
    owaspTabButton.classList.add("tab-button");
    owaspTabButton.textContent = "OWASP Top 10";
    owaspTabButton.setAttribute("data-tab", "owasp");
    document.querySelector(".tab-container").appendChild(owaspTabButton);
    
    owaspTabButton.addEventListener("click", function () {
        contents.forEach(content => content.classList.remove("active"));
        tabs.forEach(t => t.classList.remove("active"));
        this.classList.add("active");
        document.getElementById("owasp").classList.add("active");
    });
});

// This is likely in your existing code where you handle the file upload
document.getElementById('file-upload-input').addEventListener('change', function(e) {
  const file = e.target.files[0];
  const reader = new FileReader();
  
  reader.onload = function(event) {
    const content = event.target.result;
    // Parse the content and create vulnerabilityData array
    const vulnerabilityData = parseVulnerabilityData(content);
    
    // Update statistics display
    updateStatistics(vulnerabilityData);
    
    // Create your existing charts
    createSeverityChart(vulnerabilityData);
    createCvssChart(vulnerabilityData);
    createVulnTypeChart(vulnerabilityData);
    createUrlChart(vulnerabilityData);
    
    // Add the new OWASP chart here
    createOwaspChart(vulnerabilityData);
    
    // Populate the detail table
    populateVulnerabilityTable(vulnerabilityData);
    
    // Show scan info
    document.getElementById('scan-info').style.display = 'block';
  };
  
  reader.readAsText(file);
});

document.getElementById("file-upload-input").addEventListener("change", function(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    const text = e.target.result;
    const vulnerabilities = parseVulnerabilities(text);
    updateOwaspChart(vulnerabilities);
  };
  reader.readAsText(file);
});

document.querySelectorAll('.accordion-header').forEach(header => {
  header.addEventListener('click', () => {
    const content = header.nextElementSibling;
    const expanded = header.getAttribute('aria-expanded') === 'true';
    
    header.setAttribute('aria-expanded', !expanded);
    content.style.display = expanded ? 'none' : 'block';
    header.querySelector('.accordion-icon').textContent = expanded ? '+' : '−';
  });
});


document.getElementById('file-upload-input').addEventListener('change', function(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    const text = e.target.result;
    const entries = parseTxtFile(text);
    renderCVESection(entries);
  };
  reader.readAsText(file);
});

function parseTxtFile(text) {
  const lines = text.trim().split("\n");
  const data = [];

  for (let i = 1; i < lines.length; i++) {
    if (lines[i].startsWith('|')) {
      const parts = lines[i].split('|').map(p => p.trim()).filter(Boolean);
      if (parts.length >= 9) {
        const cveId = parts[3];
        const description = parts[7];
        const references = parts[8].split(',').map(ref => ref.trim());
        data.push({ cveId, description, references });
      }
    }
  }

  return data;
}

function renderCVESection(cveData) {
  const container = document.getElementById("cveSection");
  container.innerHTML = "";

  cveData.forEach((cve) => {
    const entry = document.createElement("div");
    entry.className = "cve-entry";

    const title = document.createElement("h3");
    title.textContent = cve.cveId;

    const desc = document.createElement("p");
    desc.textContent = cve.description;

    const refList = document.createElement("ul");
    cve.references.forEach(ref => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = ref;
      a.target = "_blank";
      a.textContent = ref;
      li.appendChild(a);
      refList.appendChild(li);
    });

    entry.appendChild(title);
    entry.appendChild(desc);
    entry.appendChild(refList);
    container.appendChild(entry);
  });
}


// Parse the .txt file (assuming table format with | separators)
function parseVulnerabilities(text) {
  const vulnerabilities = [];
  const lines = text.trim().split("\n");
  let isTableContent = false;

  lines.forEach((line) => {
    // Skip header and separator lines
    if (line.includes("+-") || line.includes("Page URL")) {
      isTableContent = line.includes("Page URL");
      return;
    }
    if (isTableContent && line.trim()) {
      const cols = line.split("|").map((col) => col.trim());
      if (cols.length >= 9) {
        vulnerabilities.push({
          url: cols[1],
          vulnerability: cols[2],
          attackMethod: cols[3],
          cveId: cols[4],
          severity: cols[5],
          cvssScore: parseFloat(cols[6]) || 0,
          publishedDate: cols[7],
          description: cols[8],
          references: cols[9],
        });
      }
    }
  });

  return vulnerabilities;
}

// Calculate DREAD score for a vulnerability
function calculateDREADScore(vuln) {
  // Heuristic-based scoring using available data
  let damagePotential = 5; // Default
  let reproducibility = 5;
  let exploitability = 5;
  let affectedUsers = 5;
  let discoverability = 5;

  // Damage Potential: Based on Severity and CVSS Score
  if (vuln.severity === "High") {
    damagePotential = 8;
  } else if (vuln.severity === "Medium") {
    damagePotential = 5;
  } else if (vuln.severity === "Low") {
    damagePotential = 3;
  }
  if (vuln.cvssScore >= 7) {
    damagePotential = Math.max(damagePotential, 7);
  } else if (vuln.cvssScore >= 4) {
    damagePotential = Math.max(damagePotential, 5);
  }

  // Reproducibility: Based on Attack Method
  if (vuln.attackMethod.toLowerCase().includes("automated") || vuln.attackMethod.toLowerCase().includes("script")) {
    reproducibility = 8;
  } else if (vuln.attackMethod.toLowerCase().includes("manual")) {
    reproducibility = 3;
  }

  // Exploitability: Based on CVE ID and Attack Method
  if (vuln.cveId && vuln.cveId !== "N/A") {
    exploitability = 7; // Known CVE implies exploit exists
  }
  if (vuln.attackMethod.toLowerCase().includes("simple") || vuln.attackMethod.toLowerCase().includes("public")) {
    exploitability = Math.max(exploitability, 6);
  }

  // Affected Users: Based on URL (heuristic)
  if (vuln.url.toLowerCase().includes("login") || vuln.url.toLowerCase().includes("admin")) {
    affectedUsers = 8; // Critical endpoints
  } else if (vuln.url.toLowerCase().includes("public")) {
    affectedUsers = 6;
  }

  // Discoverability: Based on URL and CVE
  if (vuln.url.toLowerCase().includes("public") || vuln.url.toLowerCase().includes("api")) {
    discoverability = 8;
  }
  if (vuln.cveId && vuln.cveId !== "N/A") {
    discoverability = Math.max(discoverability, 7); // Publicly known
  }

  // Calculate average DREAD score
  const dreadScore = (
    damagePotential +
    reproducibility +
    exploitability +
    affectedUsers +
    discoverability
  ) / 5;

  // Assign priority
  let priority = "Low";
  if (dreadScore >= 7) {
    priority = "High";
  } else if (dreadScore >= 4) {
    priority = "Medium";
  }

  return {
    damagePotential,
    reproducibility,
    exploitability,
    affectedUsers,
    discoverability,
    dreadScore: dreadScore.toFixed(1),
    priority,
  };
}

// Populate DREAD table
function populateDREADTable(vulnerabilities) {
  const tableBody = document.querySelector("#dread-table tbody");
  tableBody.innerHTML = "";

  vulnerabilities.forEach((vuln) => {
    const dread = calculateDREADScore(vuln);
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${vuln.vulnerability || "N/A"}</td>
      <td>${dread.damagePotential}</td>
      <td>${dread.reproducibility}</td>
      <td>${dread.exploitability}</td>
      <td>${dread.affectedUsers}</td>
      <td>${dread.discoverability}</td>
      <td>${dread.dreadScore}</td>
      <td style="color: ${
        dread.priority === "High" ? "#b91c1c" : dread.priority === "Medium" ? "#92400e" : "#065f46"
      }">${dread.priority}</td>
    `;
    tableBody.appendChild(row);
  });
}

// Create DREAD chart
let dreadChart = null;
function createDREADChart(vulnerabilities) {
  const ctx = document.getElementById("dread-chart").getContext("2d");

  // Destroy existing chart if it exists
  if (dreadChart) {
    dreadChart.destroy();
  }

  // Count vulnerabilities by priority
  const priorityCounts = { High: 0, Medium: 0, Low: 0 };
  vulnerabilities.forEach((vuln) => {
    const dread = calculateDREADScore(vuln);
    priorityCounts[dread.priority]++;
  });

  dreadChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["High", "Medium", "Low"],
      datasets: [
        {
          label: "Vulnerabilities by Priority",
          data: [priorityCounts.High, priorityCounts.Medium, priorityCounts.Low],
          backgroundColor: ["#b91c1c", "#92400e", "#065f46"],
          borderColor: ["#b91c1c", "#92400e", "#065f46"],
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: "Number of Vulnerabilities",
            color: "#fff",
          },
          ticks: {
            color: "#fff",
          },
          grid: {
            color: "rgba(255, 255, 255, 0.1)",
          },
        },
        x: {
          title: {
            display: true,
            text: "Priority",
            color: "#fff",
          },
          ticks: {
            color: "#fff",
          },
          grid: {
            color: "rgba(255, 255, 255, 0.1)",
          },
        },
      },
      plugins: {
        legend: {
          labels: {
            color: "#fff",
          },
        },
      },
    },
  });
}

// Handle file upload
document.getElementById("file-upload-input").addEventListener("change", function (event) {
  const file = event.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = function (e) {
      const text = e.target.result;
      const vulnerabilities = parseVulnerabilities(text);

      // Update DREAD table and chart
      populateDREADTable(vulnerabilities);
      createDREADChart(vulnerabilities);

      // Call your existing dashboard update functions here
      // e.g., updateDashboard(vulnerabilities);
    };
    reader.readAsText(file);
  }
});

// Tab switching logic
document.querySelectorAll(".tab-button").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab-button").forEach((btn) => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((content) => content.classList.remove("active"));

    button.classList.add("active");
    const tabId = button.getAttribute("data-tab");
    document.getElementById(tabId).classList.add("active");
  });
});

// WARNING: This script is designed for browser execution with an HTML file. Do not run with Node.js directly.

// Global vulnerability data
let vulnData = [];

function initializeSeverityChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) {
    console.error(`Canvas with ID ${canvasId} not found`);
    return null;
  }
  const context = canvas.getContext('2d');
  if (context) context.clearRect(0, 0, canvas.width, canvas.height);

  return new Chart(canvas, {
    type: 'pie',
    data: {
      labels: ['High', 'Medium', 'Low'],
      datasets: [{
        data: [data.high || 0, data.medium || 0, data.low || 0],
        backgroundColor: ['#b91c1c', '#92400e', '#065f46']
      }]
    },
    options: {
      plugins: { legend: { position: 'top' } }
    }
  });
}

function updateSeverityChart(chart, data) {
  if (chart) {
    chart.data.datasets[0].data = [data.high || 0, data.medium || 0, data.low || 0];
    chart.update();
  }
}

function initializeCvssChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) {
    console.error(`Canvas with ID ${canvasId} not found`);
    return null;
  }
  const context = canvas.getContext('2d');
  if (context) context.clearRect(0, 0, canvas.width, canvas.height);

  return new Chart(canvas, {
    type: 'bar',
    data: {
      labels: ['0-3', '4-6', '7-8', '9-10'],
      datasets: [{
        label: 'Vulnerabilities',
        data: data.cvssBins || [0, 0, 0, 0],
        backgroundColor: '#dbeafe'
      }]
    },
    options: {
      scales: { y: { beginAtZero: true } }
    }
  });
}

function updateCvssChart(chart, data) {
  if (chart) {
    chart.data.datasets[0].data = data.cvssBins || [0, 0, 0, 0];
    chart.update();
  }
}

function initializeVulnTypeChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) {
    console.error(`Canvas with ID ${canvasId} not found`);
    return null;
  }
  const context = canvas.getContext('2d');
  if (context) context.clearRect(0, 0, canvas.width, canvas.height);

  return new Chart(canvas, {
    type: 'bar',
    data: {
      labels: Object.keys(data.vulnTypes || {}),
      datasets: [{
        label: 'Vulnerabilities',
        data: Object.values(data.vulnTypes || {}),
        backgroundColor: '#1e40af'
      }]
    },
    options: {
      scales: { y: { beginAtZero: true } }
    }
  });
}

function updateVulnTypeChart(chart, data) {
  if (chart) {
    chart.data.labels = Object.keys(data.vulnTypes || {});
    chart.data.datasets[0].data = Object.values(data.vulnTypes || {});
    chart.update();
  }
}

function initializeUrlChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) {
    console.error(`Canvas with ID ${canvasId} not found`);
    return null;
  }
  const context = canvas.getContext('2d');
  if (context) context.clearRect(0, 0, canvas.width, canvas.height);

  return new Chart(canvas, {
    type: 'bar',
    data: {
      labels: Object.keys(data.urls || {}),
      datasets: [{
        label: 'Vulnerabilities',
        data: Object.values(data.urls || {}),
        backgroundColor: '#1e40af'
      }]
    },
    options: {
      scales: { y: { beginAtZero: true } }
    }
  });
}

function updateUrlChart(chart, data) {
  if (chart) {
    chart.data.labels = Object.keys(data.urls || {});
    chart.data.datasets[0].data = Object.values(data.urls || {});
    chart.update();
  }
}

function initializeDreadChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) {
    console.error(`Canvas with ID ${canvasId} not found`);
    return null;
  }
  const context = canvas.getContext('2d');
  if (context) context.clearRect(0, 0, canvas.width, canvas.height);

  return new Chart(canvas, {
    type: 'bar',
    data: {
      labels: data.dreadLabels || [],
      datasets: [{
        label: 'DREAD Score',
        data: data.dreadScores || [],
        backgroundColor: '#1e40af'
      }]
    },
    options: {
      scales: { y: { beginAtZero: true, max: 10 } },
      plugins: { legend: { display: false } }
    }
  });
}

function updateDreadChart(chart, data) {
  if (chart) {
    chart.data.labels = data.dreadLabels || [];
    chart.data.datasets[0].data = data.dreadScores || [];
    chart.update();
  }
}

// Handle file upload
document.getElementById('file-upload-input').addEventListener('change', (event) => {
  const file = event.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target.result;
      parseAndUpdateDashboard(text);
    };
    reader.readAsText(file);
  }
});

// Parse .txt file and update dashboard
function parseAndUpdateDashboard(text) {
  // Split lines and filter out non-data rows (e.g., headers, dividers)
  const lines = text.split('\n').filter(line => !line.includes('+--') && !line.includes('Page URL') && line.trim());
  
  vulnData = lines.map(line => {
    const cols = line.split('|').map(col => col.trim()).filter(col => col);
    return {
      url: cols[0] || '',
      vulnerability: cols[1] || '',
      attackMethod: cols[2] || '',
      cveId: cols[3] || '',
      severity: cols[4] || '',
      cvssScore: parseFloat(cols[5]) || 0,
      publishedDate: cols[6] || '',
      description: cols[7] || '',
      references: cols[8] || ''
    };
  });

  // Calculate chart data
  const total = vulnData.length;
  const high = vulnData.filter(v => v.severity.toUpperCase() === 'HIGH').length;
  const medium = vulnData.filter(v => v.severity.toUpperCase() === 'MEDIUM').length;
  const low = vulnData.filter(v => v.severity.toUpperCase() === 'LOW').length;

  document.getElementById('total-count').textContent = total;
  document.getElementById('high-count').textContent = high;
  document.getElementById('medium-count').textContent = medium;
  document.getElementById('low-count').textContent = low;

  const cvssBins = [0, 0, 0, 0]; // 0-3, 4-6, 7-8, 9-10
  vulnData.forEach(v => {
    if (v.cvssScore <= 3) cvssBins[0]++;
    else if (v.cvssScore <= 6) cvssBins[1]++;
    else if (v.cvssScore <= 8) cvssBins[2]++;
    else cvssBins[3]++;
  });

  const vulnTypes = {};
  vulnData.forEach(v => {
    vulnTypes[v.vulnerability] = (vulnTypes[v.vulnerability] || 0) + 1;
  });

  const urls = {};
  vulnData.forEach(v => {
    urls[v.url] = (urls[v.url] || 0) + 1;
  });

  // Simplified DREAD score calculation
  const dreadScores = vulnData.map(v => {
    let score = 0;
    if (v.severity.toUpperCase() === 'HIGH') score += 3;
    else if (v.severity.toUpperCase() === 'MEDIUM') score += 2;
    else if (v.severity.toUpperCase() === 'LOW') score += 1;
    score += Math.min(Math.floor(v.cvssScore / 2), 5); // Cap CVSS contribution at 5
    return Math.min(score, 10); // Cap total score at 10
  });
  const dreadLabels = vulnData.map((v, i) => v.vulnerability || `Vuln ${i}`);

  // Prepare chart data object
  const chartData = {
    high,
    medium,
    low,
    cvssBins,
    vulnTypes,
    urls,
    dreadScores,
    dreadLabels
  };

  console.log('Chart Data:', chartData); // Debug log

  // Initialize or update charts
  let severityChart = document.getElementById('severity-chart').__chart;
  severityChart = severityChart ? updateSeverityChart(severityChart, chartData) : initializeSeverityChart('severity-chart', chartData);

  let cvssChart = document.getElementById('cvss-chart').__chart;
  cvssChart = cvssChart ? updateCvssChart(cvssChart, chartData) : initializeCvssChart('cvss-chart', chartData);

  let vulnTypeChart = document.getElementById('vuln-type-chart').__chart;
  vulnTypeChart = vulnTypeChart ? updateVulnTypeChart(vulnTypeChart, chartData) : initializeVulnTypeChart('vuln-type-chart', chartData);

  let urlChart = document.getElementById('url-chart').__chart;
  urlChart = urlChart ? updateUrlChart(urlChart, chartData) : initializeUrlChart('url-chart', chartData);

  let dreadChart = document.getElementById('dread-chart').__chart;
  dreadChart = dreadChart ? updateDreadChart(dreadChart, chartData) : initializeDreadChart('dread-chart', chartData);

  // Store chart instances on canvas elements for persistence
  document.getElementById('severity-chart').__chart = severityChart;
  document.getElementById('cvss-chart').__chart = cvssChart;
  document.getElementById('vuln-type-chart').__chart = vulnTypeChart;
  document.getElementById('url-chart').__chart = urlChart;
  document.getElementById('dread-chart').__chart = dreadChart;

  // Update vulnerability table
  const tbody = document.querySelector('#vuln-table tbody');
  tbody.innerHTML = '';
  vulnData.forEach(v => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${v.url}</td>
      <td>${v.vulnerability}</td>
      <td>${v.attackMethod}</td>
      <td>${v.cveId}</td>
      <td>${v.severity}</td>
      <td>${v.cvssScore}</td>
    `;
    tbody.appendChild(row);
  });

  // Update scan info
  const scanDate = new Date().toLocaleDateString();
  document.getElementById('scan-date').textContent = `Scan Date: ${scanDate}`;
  document.getElementById('scan-info').style.display = 'block';
}

// Add event listener for export button
document.getElementById('export-pdf').addEventListener('click', async () => {
  if (!vulnData.length) {
    alert('No data available to export.');
    return;
  }

  console.log('Starting PDF export...'); // Debug log

  // Ensure charts are fully rendered
  await new Promise(resolve => setTimeout(resolve, 500)); // Wait 500ms for rendering

  const { jsPDF } = window.jspdf;
  if (!jsPDF) {
    console.error('jsPDF is not loaded. Check your script tags.');
    alert('Error: PDF library not loaded. Please ensure jsPDF is included.');
    return;
  }

  const doc = new jsPDF();
  let yOffset = 10;

  // Capture and add chart snapshots
  const charts = [
    { id: 'severity-chart', title: 'Severity Distribution' },
    { id: 'cvss-chart', title: 'CVSS Score Distribution' },
    { id: 'vuln-type-chart', title: 'Vulnerabilities by Type' },
    { id: 'url-chart', title: 'Vulnerabilities by URL' },
    { id: 'dread-chart', title: 'DREAD Score Priority' }
  ];

  for (const chart of charts) {
    const canvas = document.getElementById(chart.id);
    if (!canvas) {
      console.warn(`Canvas for ${chart.id} not found`);
      continue;
    }
    try {
      const image = await html2canvas(canvas, { scale: 2, useCORS: true }).then(canvas => canvas.toDataURL('image/png'));
      if (!image) {
        console.error(`Failed to capture image for ${chart.id}`);
        continue;
      }
      doc.addImage(image, 'PNG', 20, yOffset, 170, 80);
      doc.setFontSize(12);
      doc.text(chart.title, 20, yOffset - 5);
      yOffset += 90;

      if (yOffset > 270) {
        doc.addPage();
        yOffset = 10;
      }
    } catch (error) {
      console.error(`Error capturing ${chart.id}:`, error);
    }
  }

  // Add brief conclusion
  yOffset += 10;
  doc.setFontSize(14);
  doc.text('Conclusion', 20, yOffset);
  yOffset += 10;
  doc.setFontSize(10);
  const total = vulnData.length;
  const high = vulnData.filter(v => v.severity.toUpperCase() === 'HIGH').length;
  const medium = vulnData.filter(v => v.severity.toUpperCase() === 'MEDIUM').length;
  const low = vulnData.filter(v => v.severity.toUpperCase() === 'LOW').length;
  doc.text(`The scan identified ${total} vulnerabilities, with ${high} high-severity, ${medium} medium-severity, and ${low} low-severity issues. Immediate attention is recommended for high-severity vulnerabilities to mitigate potential risks.`, 20, yOffset);
  console.log('PDF export completed');
  doc.save('Vulnerability_Scan_Report.pdf');
});

// Initial chart setup
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  initChartsOnLoad();
} else {
  document.addEventListener('DOMContentLoaded', initChartsOnLoad);
}

function initChartsOnLoad() {
  const initialData = { high: 0, medium: 0, low: 0, cvssBins: [0, 0, 0, 0], vulnTypes: {}, urls: {}, dreadScores: [], dreadLabels: [] };
  initializeSeverityChart('severity-chart', initialData);
  initializeCvssChart('cvss-chart', initialData);
  initializeVulnTypeChart('vuln-type-chart', initialData);
  initializeUrlChart('url-chart', initialData);
  initializeDreadChart('dread-chart', initialData);
}
document.addEventListener('DOMContentLoaded', () => {
    // Login Functionality
    const loginContainer = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    const loginButton = document.getElementById('login-button');
    const logoutButton = document.getElementById('logout-button');
    const loginError = document.getElementById('login-error');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
  
    // Simple client-side credentials (for demo purposes)
    const validCredentials = {
      username: 'admin',
      password: 'password123'
    };
  
    loginButton.addEventListener('click', () => {
      const username = usernameInput.value.trim();
      const password = passwordInput.value.trim();
  
      if (username === validCredentials.username && password === validCredentials.password) {
        loginContainer.style.display = 'none';
        dashboardContainer.style.display = 'block';
        loginError.style.display = 'none';
        // Ensure the body is scrollable after login
        document.body.style.overflow = 'auto';
        // Scroll to the top of the dashboard
        window.scrollTo(0, 0);
      } else {
        loginError.style.display = 'block';
        usernameInput.value = '';
        passwordInput.value = '';
      }
    });
  
    // Handle Enter key press for login
    usernameInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') loginButton.click();
    });
    passwordInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') loginButton.click();
    });
  
    // Logout Functionality
    logoutButton.addEventListener('click', () => {
      dashboardContainer.style.display = 'none';
      loginContainer.style.display = 'flex';
      usernameInput.value = '';
      passwordInput.value = '';
      loginError.style.display = 'none';
      // Reset body overflow for login page
      document.body.style.overflow = 'auto';
      // Scroll to top of login page
      window.scrollTo(0, 0);
    });
  });
