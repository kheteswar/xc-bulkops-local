# XC App Store

A powerful, React-based internal suite designed for F5 Distributed Cloud (XC) practitioners. This App store streamlines complex configuration management in XC with various apps and scripts and professional activities like time tracking through a unified, modern interface.

---

## 🛠️ Installation & Setup

Follow these exact steps to get the environment running on your local machine.

### 1. Check Prerequisites

This tool requires **Node.js**, **npm**, **Git**, and **Homebrew** (if you are on a Mac). Open your terminal and check if they are installed by typing these commands:

```bash
node -v
npm -v
git --version
brew -v

```
### 2. Install Missing Prerequisites

If any of the commands above did not work, follow these steps to install the missing tools:

For macOS:

Homebrew: Install it first by running: /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Git: Run brew install git

Node.js & npm: Run brew install node

For Windows:

Git: Download and install from git-scm.com.

Node.js & npm: Download and run the Windows Installer (.msi) from nodejs.org.

### 3. Clone the Repository

Open your terminal and run the following command to download the source code:

```bash
git clone https://github.com/kheteswar/xc-app-store

```

### 4. Install Dependencies

Navigate into the project folder and install the required Node.js packages:

```bash
cd xc-app-store
npm install

```

### 5. Start the Application

Launch the local development server:

```bash
npm run dev

```

### 6. Access the Tool

Once the server starts, open your browser and navigate to the local URL provided in the terminal (typically):
👉 **`http://localhost:5173`**

---

## 🔄 Updating to the Latest Version

If you already have the tool cloned on your system, run the following commands from the project directory to pull the latest changes:

```bash
cd xc-app-store
git fetch origin && git reset --hard origin/main
npm install
```

> **Note:** `git reset --hard origin/main` will overwrite any local changes you may have made. If you have local modifications you want to keep, back them up first.

Then start the application as usual:

```bash
npm run dev
```

---

## 🔌 Getting Connected

Most tools require an F5 XC connection. On the home page, enter your **Tenant Name** (e.g., `my-tenant`) and **API Token**, then click **Connect**. The app validates credentials by fetching your namespace list. Once connected, all tools become available.

---

## 🛠 Tools

### 1. FP Analyzer (WAF False Positive Analyzer)

Detects false positives in WAF security events using a 7-signal scoring system.

* Select a namespace and HTTP Load Balancer, choose a time range, and click **Analyze**
* Reviews signatures, violations, bot classification, IP reputation, and threat intel
* Each event gets a confidence score — high-score events are likely false positives
* Export results as CSV or JSON for WAF exclusion rule creation

### 2. Log Analyzer

General-purpose analytics dashboard for access logs and security events.

* Select a namespace, add optional pre-fetch filters (domain, method, country, etc.), and choose a time range
* Choose log source: **Access Logs**, **Security Events**, or **Both** (merged by `req_id`)
* View summary cards (total logs, unique IPs, error rate), time series charts, and field-by-field statistics
* **Field Analysis**: Pick any field to see distributions — numeric fields show percentiles and histograms, string fields show top values with bar charts
* **Field Breakdown**: Add breakdown fields to cross-tabulate (e.g., User Agent broken down by Source IP and Country)
* Apply post-fetch client-side filters to slice data without re-fetching
* Export raw logs as JSON/CSV, or export breakdowns as CSV, Excel, or PDF

### 3. Rate Limit Advisor

Analyzes 7 days of traffic to recommend safe rate limit thresholds.

* Select a namespace and Load Balancer, then click **Analyze**
* Collects access logs and security events, computes per-IP and per-path request rates
* Generates recommended rate limit values based on observed traffic patterns (legitimate vs. suspicious)
* Export the full analysis report as PDF

### 4. DDoS Settings Advisor

Analyzes traffic patterns to recommend tuned L7 DDoS protection settings.

* Select a namespace and Load Balancer
* Scans recent traffic to find peak RPS, burst patterns, and baseline throughput
* Produces recommendations for DDoS mitigation thresholds (slow DDoS, auto-mitigation settings)
* Export report as PDF with charts and detailed findings

### 5. Config Dump

Exports the full configuration tree for any object type.

* Select a namespace, then choose an object type (HTTP LB, Origin Pool, WAF Policy, etc.)
* Fetches the object and all its referenced child objects recursively
* View the configuration tree in the browser or download as JSON or PDF

### 6. Config Viewer (Config Visualizer)

Interactive map of Load Balancer configuration and dependencies.

* Select a namespace and Load Balancer to visualize
* Displays all linked objects: origin pools, routes, WAF policies, service policies, health checks, certificates, etc.
* Click any node to inspect its full configuration

### 7. Dependency Map (Config Explorer)

Interactive relationship graph of all configuration objects in a namespace.

* Select a namespace to scan all object types and their references
* Four views: **Graph** (force-directed), **Table**, **Tree**, and **Matrix**
* Search and filter by object type to trace dependencies

### 8. Config Comparator

Side-by-side JSON diff to detect configuration drift.

* Compare objects across different namespaces or different tenants (connect a second tenant)
* Select the object type and specific objects on each side
* Highlights added, removed, and changed fields in a unified diff view

### 9. Security Auditor

Comprehensive security posture assessment for HTTP Load Balancers.

* Select one or more namespaces to audit
* Runs 30+ automated checks: TLS version, WAF mode, CORS settings, cookie security, HSTS, bot defense, DDoS protection, and more
* Results are grouped by severity (Critical, High, Medium, Low) with remediation guidance
* Export audit report as CSV or PDF

### 10. WAF Status Scanner

Quick audit of WAF deployment status across all Load Balancers.

* Select one or more namespaces to scan
* Shows each LB's WAF policy, mode (blocking/monitoring), and exclusion rule count
* Flags LBs with no WAF, WAF in monitoring mode, or excessive exclusions

### 11. HTTP Sanity Checker

Compares HTTP responses between live DNS and spoofed IP targets.

* Enter a URL and an optional spoof IP (e.g., the F5 XC VIP)
* Sends requests via live DNS resolution and via the spoofed IP
* Compares response status codes, headers, TLS certificates, and body content (fuzzy match)
* Useful for validating DNS cutover readiness

### 12. Property Viewer

View and compare a specific property across all objects of a given type.

* Select a namespace, object type, and the property path you want to inspect (e.g., `spec.waf`, `spec.domains`)
* Displays the property value for every object in a table
* Export selected rows as CSV, Excel, or JSON

### 13. HTTP LB Forge

Bulk-create HTTP Load Balancers from structured CSV input.

* Upload a CSV with columns for domain, origin pool, routes, etc.
* Preview the generated LB configurations before creating
* Creates all LBs in one batch with progress tracking

### 14. Prefix Builder

Build IP prefix sets in bulk for firewall and routing rules.

* Paste or upload a list of IP addresses/CIDRs
* Validates and deduplicates entries
* Creates the prefix set object in the selected namespace

### 15. Copy Config

Copy configuration objects across tenants or namespaces.

* Connect source and destination tenants
* Select the object type (Alert Receivers, Alert Policies, etc.)
* Pick specific objects to copy — the tool handles cross-tenant API calls

### 16. Load Tester

Stress test any HTTP endpoint with configurable parameters.

* Enter a target URL, set RPS (requests per second), concurrency, and duration
* Real-time charts showing response times, throughput, and error rates
* Standalone tool — does not require F5 XC connection

### 17. Weekly Time Tracker

Manage weekly timesheets from a single grid.

* Searchable dropdowns for Customer, Product, and Work Type
* Automatic totals for rows, days, and weekly effort
* Pre-fill from the previous week's entries
* Standalone tool — uses its own Bearer Token authentication

---

## 🏗 Architecture & Security

* **Frontend**: React 18 + TypeScript + Vite + TailwindCSS
* **Backend Proxy**: A Vite middleware proxy routes all API requests through `localhost` to bypass browser CORS restrictions. No credentials are sent to any third-party server.
* **Auth Handling**:
  * **F5 XC APIs**: `APIToken <token>` header
  * **Time Tracker APIs**: `Bearer <token>` header
* **Credentials**: Stored in browser localStorage only. Never transmitted except to the configured F5 XC tenant.
* **Rate Limiting**: Adaptive concurrency control prevents API throttling (automatic 429 backoff).

---

## 📝 Usage Notes

* **Connection**: Use the connection panel on the home page to set your Tenant Name and API Token. Credentials persist across browser sessions.
* **Read-Only vs. Write Tools**: Most tools are read-only (analyze, audit, export). Tools that create or modify objects (Prefix Builder, HTTP LB Forge, Copy Config) are clearly tagged.
* **Exports**: Many tools support export to CSV, Excel, JSON, and PDF formats via download buttons in the results section.
