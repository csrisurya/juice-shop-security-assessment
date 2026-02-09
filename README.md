# Comprehensive Security Assessment of OWASP Juice Shop

**Target**: [**OWASP Juice Shop**](https://github.com/juice-shop/juice-shop) (Intentionally Vulnerable Web Application)

---

## Project Overview

A **real-world application security assessment** demonstrating industry-standard tools and methodologies used by professional security teams. This project showcases a complete AppSec workflow from threat modeling through remediation planning.

---

## Tools & Methodologies

| Category | Tool/Framework | Purpose |
|----------|---------------|---------|
| **Threat Modeling** | STRIDE Framework | Systematic threat identification |
| | Data Flow Diagrams | Architecture visualization |
| **SAST** | Semgrep | Static code analysis for vulnerabilities |
| **SCA** | Snyk | Dependency vulnerability scanning |
| **DAST** | Burp Suite Community | Dynamic application testing |
| **AI Integration** | Claude | Research, analysis acceleration, code review |
| **Framework** | OWASP Top 10 2025 | Industry-standard vulnerability classification |

---

## Executive Summary

### Findings Overview

| Severity | SAST (Semgrep) | SCA (Snyk) | Total |
|----------|----------------|------------|-------|
| **CRITICAL** | 3 | 5 | **8** |
| **HIGH** | 6 | 23 | **29** |
| **MEDIUM** | 28 | 32 | **60** |
| **LOW** | 3 | 3 | **6** |
| **TOTAL** | **40** | **63** | **103** |

### Top Critical Findings

1. **SQL Injection (Authentication Bypass)** - CRITICAL
   - Confirmed exploit in login endpoint
   - Complete authentication bypass achieved
   - OWASP: Injection

2. **Insecure Direct Object Reference (IDOR)** - CRITICAL
   - Access to other users' shopping baskets
   - No authorization checks on basket endpoint
   - OWASP: Broken Access Control

3. **Remote Code Execution in vm2** - CRITICAL
   - 3 RCE CVEs in dependency
   - Sandbox bypass enabling server compromise
   - OWASP: Vulnerable Components

4. **JWT Authentication Bypass** - CRITICAL
   - Hardcoded secret (SAST) + Authentication bypass CVE (SCA)
   - Combined vulnerability enables complete auth failure
   - OWASP: Authentication Failures

5. **Code Injection via eval()** - CRITICAL
   - User input flows to eval() function
   - Enables arbitrary code execution
   - OWASP: Injection

### OWASP Top 10 2025 Coverage

| Category | Findings | Status |
|----------|----------|--------|
| **Broken Access Control** | 7 | Multiple issues confirmed |
| **Cryptographic Failures** | 3 |  Weak hashing, JWT issues |
| **Injection** | 18 | SQL, XSS, Code injection |
| **Insecure Design** | 4 | Missing security controls |
| **Security Misconfiguration** | 8 | Directory listing, errors |
| **Vulnerable Components** | 63 | Comprehensive SCA scan |
| **Authentication Failures** | 14 | Multiple auth bypass vectors |
| **Software/Data Integrity** | 2 | Limited coverage |
| **Logging & Monitoring** | 1 | Identified in threat model |
| **SSRF** | 0 | Not detected |

**Coverage**: 8 out of 10 categories with 103 findings

---

## Methodology

### Phase 1: Threat Modeling with STRIDE

#### [Data Flow Diagram](threat-model/data-flow-diagram.png)
Created architecture diagram identifying:
- External entities (User, Web Browser)
- Processes (Web App, Auth Service)  
- Data stores (SQLite Database, File System)
- Trust boundaries

#### [STRIDE Analysis and Validation](threat-model/stride-analysis.md)
Focused on 3 critical components with **manual exploitation using Burp Suite**:

**Component 1: Web Application**

1. **Information Disclosure** (**VALIDATED**)
   - **Threat**: Verbose error messages reveal system details
   - **Validation**: Sent `'` as username in Burp
   - **Result**: Error exposed SQLite database and SQL query structure
   ```
   "SQLITE_ERROR: unrecognized token..."
   SQL: "SELECT * FROM Users WHERE email = ''' AND password = '...' AND deletedAt IS NULL"
   ```

2. **Elevation of Privilege (IDOR)**  (**VALIDATED**)
   - **Threat**: Access other users' data without authorization
   - **Validation**: Changed basket ID in localStorage from 5 to 1
   - **Result**: Successfully accessed admin's basket
   - **OWASP**: A01:2025 - Broken Access Control

**Component 2: Authentication Service**

3. **Spoofing Identity (SQL Injection)** (**VALIDATED**)
   - **Threat**: Bypass authentication mechanism
   - **Validation**: Login with `' OR 1=1--` as email
   - **Result**: Logged in as admin without valid credentials
   - **OWASP**: A05:2025 - Injection

4. **Exposed Admin Panel** (**VALIDATED**)
   - **Validation**: Accessed `/#/administration` without authentication
   - **Result**: Admin panel visible (frontend-only protection)

**Component 3: Database**

5. **Tampering + Information Disclosure**
   - **Threat**: SQL injection for data extraction
   - **Attack Vector**: Product search with `UNION SELECT`
   - **Status**: Identified but not fully exploited (time constraint)

**Validation Rate**: 4 out of 5 threats confirmed (80%)

---

### Phase 2: SAST - Static Analysis with Semgrep

#### Scans Performed
```bash
semgrep --config=auto
semgrep --config=p/owasp-top-ten
semgrep --config=p/sql-injection
semgrep --config=p/xss
```

#### [SAST Analysis Report](sast-analysis/sast-analysis-findings.md) Critical Findings

**1. SQL Injection - Login Endpoint**
- **File**: `routes/login.ts:34`
- **Issue**: Direct string concatenation of user input
- **Exploit**: `' OR 1=1--` bypasses authentication
- **Validation**: Confirmed in manual testing

**2. SQL Injection - Search Endpoint**
- **File**: `routes/search.ts:23`
- **Issue**: Unsanitized search criteria in SQL query
- **Potential Exploit**: `' UNION SELECT * FROM Users--`

**3. Hardcoded JWT Secret**
- **File**: `lib/insecurity.ts:56`
- **Issue**: Weak, hardcoded secret enables token forgery
- **Cross-reference**: Combines with SCA JWT bypass CVE

**4. Code Injection via eval()**
- **File**: `routes/userProfile.ts:62`
- **Impact**: Remote code execution potential

**5. XSS in Chatbot Route**
- **File**: `routes/chatbot.ts:197`
- **Issue**: Unsanitized HTML rendering

**6. Directory Listing Enabled**
- **File**: `server.ts:269`
- **Validation**: Confirmed via accessing `/ftp` endpoint

#### SAST Statistics
- **Total Findings**: 40 (excluding test files)
- **ERROR Severity**: 9
- **WARNING Severity**: 28
- **INFO Severity**: 3
- **False Positive Rate**: ~10%
---

### Phase 3: SCA - Dependency Scanning with Snyk

**Command**: `snyk test > snyk-report.txt`

#### [SCA Analysis Report](sca-analysis/sca-analysis-findings.md) Critical Vulnerabilities

**1. Remote Code Execution in vm2@3.9.17** 
- **CVEs**: 4 (3 RCE, 1 Sandbox Bypass)
- **CVSS**: 9.8 (Critical)
- **Impact**: Complete server compromise
- **Status**: No direct upgrade (dependency issue)

**2. Uncaught Exception in multer@1.4.5** 
- **CVE**: SNYK-JS-MULTER-10299078
- **Impact**: Application crash (DoS)
- **Fix**: Upgrade to multer@2.0.2

**3. JWT Authentication Bypass** 
- **Packages**: express-jwt@0.1.3, jsonwebtoken@0.1.0
- **CVEs**: 12 vulnerabilities
- **Impact**: Complete authentication bypass
- **Cross-reference**: Validates SAST hardcoded secret finding
- **Fix**: Upgrade to latest versions

**4. Prototype Pollution in lodash@2.4.2** 
- **CVEs**: 9 vulnerabilities
- **Impact**: Privilege escalation, code injection
- **Fix**: Upgrade sanitize-html (updates lodash transitively)

**5. XSS Vulnerabilities in sanitize-html@1.4.2**
- **CVEs**: 15 vulnerabilities
- **Impact**: Stored XSS, session hijacking
- **Fix**: Upgrade to sanitize-html@2.12.1

#### SCA Statistics
- **Dependencies Scanned**: 1,000
- **Vulnerabilities Found**: 63
- **Vulnerable Paths**: 88
- **Upgradable**: 45 (71%)
- **No Patch Available**: 18 (29%)

**Key Insight**: SCA identified vulnerabilities in dependencies that SAST cannot detect, demonstrating the need for multiple security testing approaches.

---

## Cross-Tool Validation

One of the strengths of this assessment is **cross-referencing findings** across tools and manual validation:

| Finding | SAST | SCA | Manual Test | Validation |
|---------|------|-----|-------------|------------|
| SQL Injection (Login) | Found | Not Found | Exploited | **Confirmed** |
| Hardcoded JWT Secret | Found | CVE |  Analyzed | **Cross-validated** |
| IDOR (Basket Access) | Not Found | Not Found | Exploited | **Runtime-only** |
| XSS in Chatbot | Found | CVE | Partial | **Multi-tool** |
| Weak Crypto (MD5) | Found | CVE | Not Found | **SAST+SCA** |
| Directory Listing | Found | Not Found | Observed | **SAST validated** |
| Info Disclosure (Errors) | Found | Not Found | Confirmed | **SAST+Manual** |

**Validation Rate**: 71% of findings confirmed through multiple methods

**Insight**: Each tool has blind spots. SAST misses runtime issues (IDOR), SCA misses custom code flaws. Manual testing validates exploitability. A comprehensive assessment requires all approaches.

---

## Risk Prioritization Matrix

### Critical Priority (Fix Immediately)

| # | Finding | Impact | Exploitability | Business Risk |
|---|---------|--------|----------------|---------------|
| 1 | SQL Injection (Login) | Authentication bypass | Trivial (confirmed) | Data breach, compliance violation |
| 2 | IDOR (Basket Access) | Unauthorized data access | Easy (confirmed) | Privacy violation, fraud |
| 3 | vm2 RCE | Complete server compromise | Public exploits | Total system loss |
| 4 | JWT Auth Bypass | Token forgery | Medium (CVE + hardcoded secret) | Account takeover at scale |

**Remediation Steps**:
```bash
1. Fix SQL Injection
Replace string concatenation with parameterized queries in:
routes/login.ts
routes/search.ts

2. Fix IDOR
Add authorization middleware to basket routes

3. Fix Dependencies
npm install multer@2.0.2
npm install express-jwt@7.7.8 jsonwebtoken@9.0.0

4. Fix JWT Secret
Move to environment variable, generate 256-bit random secret
```

---

### High Priority (Fix This Sprint)

| Finding | Remediation |
|---------|-------------|
| Code Injection (eval) | Remove eval() usage or use vm2 sandbox properly |
| XSS in Chatbot | Implement DOMPurify sanitization |
| Prototype Pollution (lodash) | Upgrade sanitize-html@2.12.1 |
| Directory Listing | Disable serveIndex middleware |
| Socket.io DoS | Upgrade to socket.io@4.8.0 |

---

### Medium Priority (Plan for Next Sprint)

- Open redirect vulnerability
- ReDoS in multiple packages
- Directory traversal in tar
- Missing security headers
- Insufficient logging

---

## Remediation Guide

### SQL Injection Fix

**Before (Vulnerable)**:
```javascript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' 
   AND password = '${security.hash(req.body.password)}'`
)
```

**After (Secure)**:
```javascript
models.sequelize.query(
  'SELECT * FROM Users WHERE email = ? AND password = ?',
  {
    replacements: [req.body.email, security.hash(req.body.password)],
    type: models.sequelize.QueryTypes.SELECT
  }
)
```

---

### IDOR Fix

**Before (Vulnerable)**:
```javascript
app.get('/rest/basket/:id', (req, res) => {
  BasketModel.findOne({ where: { id: req.params.id } })
    .then(basket => res.json(basket))
})
```

**After (Secure)**:
```javascript
app.get('/rest/basket/:id', isAuthenticated, (req, res) => {
  BasketModel.findOne({ 
    where: { 
      id: req.params.id,
      UserId: req.user.id  // Verify ownership
    } 
  })
  .then(basket => {
    if (!basket) return res.status(404).send('Not found')
    res.json(basket)
  })
})
```

---

### JWT Secret Fix

**Before (Vulnerable)**:
```javascript
const JWT_SECRET = 'too short and easily guessable'
```

**After (Secure)**:
```javascript
// .env file
JWT_SECRET=a3f8b2c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0

// config.js
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET || JWT_SECRET.length < 64) {
  throw new Error('JWT_SECRET must be at least 256 bits')
}
```

---

## Repository Structure

```
juice-shop-security-assessment/
├── README.md                          # This file (Final Report)
├── threat-model/
│   ├── data-flow-diagram.png          # Architecture diagram
│   └── stride-analysis.md             # STRIDE analysis + manual test results
├── sast-analysis/
│   ├── findings.md                    # Semgrep results analysis
│   └── semgrep-results.json           # Raw scan output
└── sca-analysis/
    ├── findings.md                    # Snyk results analysis
    └── snyk-results.txt               # Raw scan output
```

---

## References & Learning Resources

### Frameworks & Standards
- **OWASP Top 10 2025**: https://owasp.org/Top10/
- **STRIDE Threat Modeling**: Microsoft Security Development Lifecycle
- **Adam Shostack**: https://www.youtube.com/watch?v=2pvprvsr1lo&list=PLCVhBqLDKoOOZqKt74QI4pbDUnXSQo0nf$0
- **CWE Top 25**: https://cwe.mitre.org/top25/

### Tools Documentation
- **Semgrep**: https://semgrep.dev/docs/
- **Snyk**: https://docs.snyk.io/
- **Burp Suite**: https://portswigger.net/burp/documentation
- **Sequelize Security**: https://sequelize.org/docs/v6/core-concepts/raw-queries/

### Security Cheat Sheets
- **OWASP Cheat Sheet Series**: https://cheatsheetseries.owasp.org/
- **SQL Injection Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **XSS Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
