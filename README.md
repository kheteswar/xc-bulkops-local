# XC App Store
> A centralized hub for specialized apps and scripts designed for bulk operations and advanced tasks in F5 Distributed Cloud (XC).

**Repository:** [https://github.com/kheteswar/xc-bulkops-local.git](https://github.com/kheteswar/xc-bulkops-local.git)

A comprehensive, developer-centric toolkit designed to streamline operations, automate security auditing, and simplify bulk configuration management for **F5 Distributed Cloud (XC)**. 

This React-based application acts as a "power console" that sits on top of the standard F5 XC API, filling the gaps for bulk operations, deep visibility, and rapid object creation.

---

## 🚀 Key Features

This dashboard includes **8 specialized tools**:

### 1. 🧱 Prefix Builder (Advanced)
A robust engine for managing IP blocking and allow-listing at scale.
* **Bulk Processing:** Import `.txt` or `.csv` files containing thousands of IPs/CIDRs.
* **Auto-Splitting:** Automatically detects if an IP list exceeds the F5 XC API limit (1024 IPs per object) and splits them into multiple objects (e.g., `blocklist-1`, `blocklist-2`) while keeping them logically grouped.
* **Smart Policy Attachment:** * Can create a **new Service Policy** or update an **existing one**.
    * Handles the complex API schema transition from "Simple Mode" (`deny_list`) to "Advanced Mode" (`rule_list`) automatically to ensure compatibility.
    * Supports explicitly setting rules to **Allow** or **Deny**.
* **Validation:** Validates IPv4/IPv6 formats and prevents duplicate entries.

### 2. 🛡️ Security Auditor
An automated compliance engine that scans your Load Balancers against industry best practices.
* **Rule Engine:** Evaluates configurations based on:
    * **TLS/SSL:** Checks for HSTS headers, TLS 1.2+ enforcement, and valid certificates.
    * **WAF:** Verifies WAF is attached and running in **Blocking** mode.
    * **Origin Pools:** Checks for TLS usage on the origin side.
    * **Bot Defense:** Ensures Bot defense policies are active.
    * **Logging:** Validates that appropriate access logs are enabled.
* **Reporting:** Generates a granular pass/fail report with severity levels.

### 3. ⚖️ Config Comparator
A "Diff" tool for F5 XC objects (JSON Specifications).
* **Cross-Context Comparison:** Compare objects between different namespaces or even completely different **Tenants**.
* **Visual Diff:** Highlights specific lines (Additions in Green, Deletions in Red) in the JSON spec, making it essential for auditing changes before promoting from `staging` to `production`.

### 4. 👁️ Config Visualizer
A graph-based dependency mapper.
* **Topology View:** Visualizes the complex web of relationships between a Load Balancer and its child objects (WAF Policies, Origin Pools, Certificates, Routes).
* **Interactive:** Click on nodes to reveal object metadata and status.

### 5. 🔍 WAF Scanner
A high-level operational dashboard for WAF status.
* **Fleet Overview:** Scans all HTTP Load Balancers in a namespace.
* **Status Indicators:** Instantly categorizes LBs into:
    * 🔴 **No WAF:** Vulnerable.
    * 🟡 **Monitoring:** WAF present but not blocking.
    * 🟢 **Blocking:** Protected.

### 6. 📋 Property Viewer
A spreadsheet-style attribute explorer.
* **Grid View:** Flattens the complex JSON structure of Load Balancers into a sortable table.
* **Quick Audit:** Easily see columns for "Domains", "HSTS Enabled", "WAF Mode", and "Certificate Expiry" across your entire fleet in one view.

### 7. 🚚 Copy Config
A migration helper utility.
* **Deep Cloning:** Copies complex objects (like Alert Policies, Alert Receivers) from one namespace to another.
* **Dependency Handling:** (Note: Future roadmap often includes resolving child dependencies during copy).

### 8. 🧪 HTTP Sanity Checker
A live traffic validation tool.
* **Live Headers:** Makes real HTTP requests to your applications.
* **Security Baseline:** Compares the actual response headers against a security baseline (e.g., checking for `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`).

---

## 🛠️ Technology Stack

* **Frontend:** [React](https://reactjs.org/) (v18)
* **Language:** [TypeScript](https://www.typescriptlang.org/)
* **Build Tool:** [Vite](https://vitejs.dev/)
* **Styling:** [Tailwind CSS](https://tailwindcss.com/)
* **Icons:** [Lucide React](https://lucide.dev/)
* **Routing:** [React Router DOM](https://reactrouter.com/)
* **API Client:** Custom TypeScript wrapper around `fetch` with local proxy support.

---

## ⚙️ Installation & Setup

### 1. Prerequisites
* Node.js (v16.0.0 or higher)
* npm or yarn
* An F5 Distributed Cloud Account (Tenant URL + API Token).

### 2. Clone the Repository
```bash
git clone [https://github.com/kheteswar/xc-bulkops-local.git](https://github.com/kheteswar/xc-bulkops-local.git)
cd xc-bulkops-local