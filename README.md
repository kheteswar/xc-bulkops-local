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

### 5. Access the Tool

Once the server starts, open your browser and navigate to the local URL provided in the terminal (typically):
👉 **`http://localhost:5173`**

---

## 🛠 Features

### 1. Weekly Time Tracker

Designed to eliminate the friction of manual time entry, this tool allows you to manage an entire week's timesheet from a single grid.

* **Searchable Dropdowns**: Quickly find Customers, Products, and Work Types by typing.
* **Smart Upsert Logic**: Automatically detects if an entry is new, needs an update, or should be deleted.
* **Manual Pre-fill**: Use the "Pre-fill from Last Week" button to instantly copy over account combinations used in the previous 7 days.
* **Automatic Totals**: Real-time calculation of row totals, daily totals, and overall weekly effort.
* **Session Security**: Option to remember your Bearer Token locally for seamless future access.

### 2. Property Viewer

Analyze and compare specific object properties across different F5 XC namespaces in a report-style view.

* **Deep Inspection**: View full raw JSON configurations for any object directly in the tool.
* **Selective Export**: Select specific data points and export them to CSV, Excel, or JSON formats.

### 3. Security Auditor & WAF Scanner

* **Security Auditor**: Runs automated checks against HTTP Load Balancer configurations to identify non-compliant security settings (e.g., weak TLS versions, WAF in monitoring mode).
* **WAF Scanner**: Rapidly scans multiple namespaces to validate and report on the status of Web Application Firewall policies.

### 4. Utilities

* **HTTP LB Forge**: Build complex Load Balancer configurations using structured templates.
* **Sanity Checker**: Test DNS and HTTP connectivity, supporting both live lookups and spoofed IP targets.
* **Config Comparator**: A side-by-side JSON comparison utility to detect configuration drift between objects.

---

## 🏗 Architecture & Security

* **Frontend**: React 18 with TypeScript for robust type safety.
* **Styling**: Modern, responsive dark-themed UI powered by TailwindCSS and Lucide Icons.
* **Backend Proxy**: A custom Vite middleware proxy routes all API requests through your local server to bypass browser CORS restrictions.
* **Auth Handling**: The proxy intelligently manages different authentication standards:
* **F5 XC APIs**: Uses `APIToken <token>` header.
* **Time Tracker APIs**: Uses `Bearer <token>` header.



---

## 📝 Usage Notes

* **Settings**: Use the **Settings (gear icon)** in each tool to update your Tenant ID or API Tokens.
* **Hardcoded Endpoints**: The Time Tracker is hardcoded to route through the secure proxy at `time-tracker.mgdsvc-ai.f5sdclabs.com` to ensure data integrity.
