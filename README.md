# 🛡️ WP-Dex — Advanced WordPress Passive Recon Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Status-Stable-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-Educational-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/Security-Passive%20Recon-red?style=for-the-badge">
</p>

> ⚡ Deep reconnaissance • Passive scanning • Zero exploitation  
> WP-Dex is a powerful Python-based tool designed to gather detailed intelligence about WordPress websites without modifying or attacking the target.

---

## 📸 Preview

### 🔍 Banner
![Scan Output](./images/banner.png)

---

### 🔍 Scan Output
![Report Output](./images/Screenshot1.png)

---

## 🚀 What is WP-Dex?

WP-Dex is a passive reconnaissance tool built for security researchers, developers, and ethical hackers.  
It collects publicly accessible data from WordPress websites and presents it in a structured, readable format.

Unlike aggressive tools, WP-Dex does NOT exploit vulnerabilities — it only reveals what is already exposed.

---

### 🔍 Scan Output
![Report Output](./images/Screenshot3.png)

---

## 🧠 What Does It Do?

### 🔎 WordPress Detection
Confirms if a target is running WordPress using multiple indicators.

### 🖥️ Server & Technology Fingerprinting
Detects server type, PHP version, CDN/WAF, and technologies like jQuery, Bootstrap, WooCommerce, Elementor.

### 🔢 WordPress Version Detection
Extracts version from meta tags, feeds, readme files, and scripts.

### 👤 User Enumeration
Discovers usernames via REST API, author ID, sitemaps, and oEmbed.

### 📧 Email Harvesting
Extracts emails from page content and mailto links.

### 🔌 Plugin Detection
Finds plugins via source analysis, probing, and database matching.

### 🎨 Theme Detection
Identifies themes and extracts metadata like version and author.

### 🗺️ Site Structure Mapping
Maps pages, posts, categories, tags, and menus.

### 🌐 Social & Contact Info
Extracts social profiles and phone numbers.

### ⚠️ Vulnerability Matching
Matches plugins with known CVEs using offline database.

### 🔒 Security Checks
Checks exposed paths and analyzes HTTP security headers.

---

### 🔍 Scan Output
![Report Output](./images/Screenshot4.png)

---

## ⚙️ Installation

```bash
git clone https://github.com/DotX-47/WP-Dex.git
cd WP-Dex
pip install requests beautifulsoup4
```

---

## ▶️ Usage

```bash
python WP-Dex https://example.com
```

---

### 🔍 Scan Output
![Report Output](./images/Screenshot2.png)

---

## 📂 Output

- Terminal (structured output)
- JSON report (optional)

---

## ⚠️ Disclaimer

Use only on websites you own or have permission to test.

---

## 👨‍💻 Author

DotX-47
