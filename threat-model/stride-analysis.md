# STRIDE Threat Analysis
**Framework**: STRIDE
**Reference**: OWASP Top 10 2025

---

## Component 1: Juice Shop Web Application

### I - Information Disclosure
**Threat**: Verbose error messages and exposed endpoints reveal system information

**OWASP 2025**: Security Misconfiguration

**Evidence**:
1. **SQL Error Leakage**:  
    1. Intercepted HTTP request in Burp
    2. Entered ' as username and random string as password
```
   Search: '
   Message: "SQLITE_ERROR: unrecognized token: \"3590cb8af0bbb9e78c343b52b93773c9\"
   SQL: "SELECT * FROM Users WHERE email = ''' AND password = '3590cb8af0bbb9e78c343b52b93773c9' AND deletedAt IS NULL"
   Reveals: SQLite database in use
```

2. **Exposed Admin Panel**:
    1. Look for application logic files (Developer Tools -> Sources -> main.js)
    2. Search for 'path'
    3. specifies 'administration' as one of the path   
```
   URL: http://localhost:3000/#/administration
   Status: Accessible (should require admin role)
```

**Mitigation**: 
- Generic error messages in production
- Proper authentication on admin routes
- Disable directory listing

---

### E - Elevation of Privilege
**Threat**: User gains unauthorized access to higher privileges

**Attack Scenarios**: IDOR to access other users' baskets

**OWASP 2025 Mapping**: Broken Access Control, Injection

**Evidence in Juice Shop**:
- Login as user and change basket id in LocalStorage (using Developer Tools) to 1 -> Refresh -> Access to Admin basket  

**Mitigation**:
- Implement proper authorization checks on all endpoints
- Use UUIDs instead of sequential IDs

---

## Component 2: Authentication Service

### S - Spoofing Identity
**Threat**: Bypass authentication mechanism

**Attack Scenarios**: SQL injection login bypass

**OWASP 2025 Mapping**: Authentication Failures, Injection

**Evidence in Juice Shop**:
```sql
-- Login bypass payload
Email: ' OR 1=1--
Password: anything
Result: Successfully logged in as first user (admin)
```

**Mitigation**: Parameterized SQL queries

---

## Component 3: Database (SQLite)

### T + I - Tampering & Information Disclosure (TODO)
**Threat**: SQL Injection allows data extraction and modification

**OWASP 2025**: Injection

**Attack Vector**: Exploitation via search box

**UNION-based SQL Injection**:

```
UNION SELECT 1,2,3... from Users
```

**Expected Result**: Extract all user credentials

**Mitigation**: 
- Parameterized queries
- Encrypt sensitive data at rest
---