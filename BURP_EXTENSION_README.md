# GQLSweep Burp Suite Extension

A comprehensive GraphQL security testing extension for Burp Suite, based on the standalone gqlSweep tool.

![Python](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Jython](https://img.shields.io/badge/Jython-2.7-blue)

## Features

- **Right-Click Context Menu**: Test GraphQL endpoints directly from any Burp Suite window
- **170+ Security Tests**: Comprehensive vulnerability testing including:
  - Introspection attacks
  - DoS (Denial of Service)
  - SQL/NoSQL/Command Injection
  - Authorization & Access Control (BOLA/IDOR)
  - XSS (Cross-Site Scripting)
  - SSRF (Server-Side Request Forgery)
  - Business Logic flaws
  - Cryptography issues
  - File handling vulnerabilities
  - And more...
- **Real-Time Scanner UI**: Visual progress tracking with live updates
- **Color-Coded Results**: Easy-to-identify vulnerabilities by severity
  - 🔴 **Critical**: Red highlight
  - 🟠 **High**: Orange highlight
  - 🟡 **Medium**: Yellow highlight
  - 🔵 **Low**: Cyan highlight
  - ℹ️ **Info**: Blue highlight
- **Detailed Request/Response View**: Inspect raw HTTP traffic for each test
- **Statistics Dashboard**: Track total tests, vulnerabilities, and severity breakdown

## Installation

### Prerequisites

1. **Burp Suite Professional or Community Edition**
2. **Jython Standalone JAR** (for Python extensions)

### Step 1: Download Jython

1. Download Jython standalone JAR from: https://www.jython.org/download.html
   - Get the latest `jython-standalone-2.7.x.jar`
2. Save it to a location you can remember (e.g., `~/jython-standalone-2.7.3.jar`)

### Step 2: Configure Burp Suite

1. Open **Burp Suite**
2. Go to **Extensions** → **Extension Settings**
3. Under **Python Environment**, click **Select file**
4. Browse and select the `jython-standalone-2.7.x.jar` file you downloaded
5. Click **OK**

### Step 3: Load the Extension

1. Go to **Extensions** → **Installed**
2. Click **Add**
3. In the dialog:
   - **Extension type**: Select **Python**
   - **Extension file**: Browse and select `burp_gqlsweep.py`
4. Click **Next**
5. Check the **Output** tab for any errors. You should see:
   ```
   [+] GQLSweep Extension Loaded Successfully!
   [+] Right-click on any request to start GraphQL security scan
   ```

## Usage

### Method 1: Right-Click Context Menu

1. **Navigate to any Burp tool** (Proxy History, Target Site Map, Repeater, etc.)
2. **Right-click on a GraphQL request** (POST request to `/graphql` endpoint)
3. Select **Extensions** → **Test all GraphQL Injections at once**
4. The scan will start automatically, and you'll be switched to the **GQLSweep** tab

### Method 2: From the GQLSweep Tab

1. **Capture a GraphQL request** in Burp (Proxy, Target, etc.)
2. **Right-click and select** "Test all GraphQL Injections at once"
3. **Switch to the GQLSweep tab** to view results

## Understanding the UI

### Top Section: Scanner Status

- **Title**: "GQLSweep - GraphQL Security Scanner"
- **Progress Bar**: Real-time scanning progress
- **Statistics**:
  - Total Tests: Number of tests executed
  - Vulnerabilities: Number of findings detected
  - Critical/High/Medium/Low: Severity breakdown

### Middle Section: Results Table

Displays all test results with the following columns:

| Column | Description |
|--------|-------------|
| **ID** | Test identifier (e.g., `INTRO-01`, `INJ-SQL-01`) |
| **Name** | Descriptive test name |
| **Severity** | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| **Status** | `VULN` (vulnerable) or `PASS` (no issue found) |
| **HTTP Code** | Response status code (200, 500, etc.) |
| **Time (s)** | Response time in seconds |
| **Finding** | Brief description of the vulnerability |

**Color Coding:**
- Rows with vulnerabilities are highlighted based on severity
- Passed tests show white background
- Click any row to view details

### Bottom Section: Request/Response Details

**Left Panel - Request:**
- GraphQL Query
- Variables (if any)
- Full HTTP Request

**Right Panel - Response:**
- Finding summary
- HTTP status code
- Response time
- Response body (truncated to 5000 chars)

## Test Categories

The extension runs 170+ tests across these categories:

### 1. Introspection Tests (10 tests)
- Basic schema introspection
- Full schema dump attempts
- Deep nested introspection
- Directive enumeration

### 2. Denial of Service (20 tests)
- Query batching
- Alias overloading
- Deep recursion
- Circular fragments
- Field duplication

### 3. Injection Attacks (35+ tests)
- **SQL Injection**: UNION, time-based, error-based
- **NoSQL Injection**: MongoDB operators, regex
- **Command Injection**: Shell commands, backticks
- **LDAP/XXE/XPath**: Entity expansion, path injection
- **GraphQL Injection**: Directive/fragment abuse

### 4. Authorization & Access Control (15 tests)
- IDOR/BOLA (Broken Object Level Authorization)
- Privilege escalation
- Horizontal/vertical privilege bypass
- Mass assignment
- Tenant isolation bypass

### 5. Information Disclosure (15 tests)
- Stack trace exposure
- Debug information leakage
- Internal type enumeration
- Verbose error messages

### 6. Cross-Site Scripting (10 tests)
- Reflected XSS
- Stored XSS
- Polyglot payloads
- Unicode escapes

### 7. SSRF (15 tests)
- AWS/GCP/Azure metadata
- Internal network scanning
- File protocol abuse
- Cloud API probing

### 8. CSRF (10 tests)
- Origin header manipulation
- Referer bypass
- Content-type abuse

### 9. Business Logic (12 tests)
- Negative pricing
- Quantity tampering
- Race conditions
- Currency manipulation

### 10. Cryptography (10 tests)
- JWT algorithm confusion
- Weak secrets
- Token expiration bypass

### 11. File Handling (10 tests)
- Path traversal
- Null byte injection
- Zip bombs
- SVG XSS

### 12. Relay Patterns (8 tests)
- Node ID manipulation
- Cursor prediction
- Connection pagination abuse

## How It Works

1. **Request Capture**: The extension captures your selected GraphQL request
2. **Test Generation**: Generates 170+ test cases based on:
   - Generic GraphQL attacks
   - Schema introspection attempts
   - Argument fuzzing (if original query has arguments)
3. **Execution**: Sends each test to the target endpoint using Burp's HTTP engine
4. **Analysis**: Analyzes responses for:
   - Error messages (SQL, NoSQL, stack traces)
   - Reflected payloads (XSS)
   - Information disclosure (schema data, debug info)
   - Anomalous behavior (status codes, response times)
5. **Reporting**: Color-codes results and displays findings in real-time

## Example Workflow

1. **Browse target application** with Burp proxy enabled
2. **Find a GraphQL request** in Proxy History (usually POST to `/graphql`)
3. **Right-click → Extensions → Test all GraphQL Injections at once**
4. **Monitor progress** in the GQLSweep tab
5. **Review vulnerabilities**:
   - Click on red/orange highlighted rows first (Critical/High)
   - Examine the request/response details
   - Verify findings manually if needed
6. **Export results** (screenshot or copy details for reporting)

## Tips & Best Practices

### Identifying GraphQL Endpoints

Look for requests with:
- URL path: `/graphql`, `/api/graphql`, `/v1/graphql`
- Content-Type: `application/json`
- POST body containing: `{"query": "...", "variables": {...}}`

### Interpreting Results

- **False Positives**: Some tests may trigger generic errors. Always verify manually.
- **Focus on Severity**: Prioritize CRITICAL and HIGH findings
- **Context Matters**: Some tests (like IDOR) require valid IDs to be meaningful
- **Response Times**: Look for anomalies in response times (potential time-based attacks)

### Performance

- **Scan Duration**: 170+ tests may take 2-10 minutes depending on:
  - Network latency
  - Server response times
  - Number of arguments to fuzz
- **Concurrent Requests**: Extension sends requests sequentially to avoid overwhelming the server
- **Rate Limiting**: If you see many 429 errors, the server has rate limiting enabled

## Troubleshooting

### Extension Won't Load

1. **Check Jython configuration** in Extensions → Extension Settings
2. **Verify Python path** points to `jython-standalone-2.7.x.jar`
3. **Check Output tab** for error messages
4. **Reload extension**: Remove and re-add the extension

### No Context Menu Item

1. **Ensure you're right-clicking on a request** (not a folder or domain)
2. **Try different contexts**: Proxy History, Target Site Map, Repeater
3. **Reload the extension**

### Scan Not Starting

1. **Check Burp's alerts** for connection errors
2. **Verify target is accessible** (try a manual request in Repeater)
3. **Check if GraphQL endpoint is valid**

### No Vulnerabilities Found

This could mean:
- The endpoint is well-secured (good!)
- Introspection is disabled
- WAF/security controls are blocking attacks
- The endpoint isn't actually GraphQL

## Limitations

- **Jython 2.7**: Uses Python 2.7 syntax (Burp limitation)
- **No Authentication Auto-Refresh**: If auth tokens expire during scan, some tests may fail
- **Limited Response Analysis**: May miss context-specific vulnerabilities
- **No Custom Payloads**: Uses predefined payload set (can be extended by editing the code)

## Customization

You can customize the extension by editing `burp_gqlsweep.py`:

### Add Custom Test Cases

In `TestCaseGenerator` class, add new tests in relevant methods:

```python
def _generate_custom_tests(self):
    self.add_test("CUSTOM-01", "My Test", "HIGH",
                 "Custom test description",
                 "query { myCustomQuery { field } }")
```

Then call it in `generate_all()`:

```python
def generate_all(self):
    # ... existing tests ...
    self._generate_custom_tests()
    return self.tests
```

### Modify Color Coding

In `ColoredCellRenderer` class, adjust colors:

```python
if severity == "CRITICAL":
    component.setBackground(Color(220, 53, 69, 40))  # Change RGB values
```

### Adjust Analysis Logic

In `_analyze_response()` method, add custom detection patterns:

```python
if "your_custom_pattern" in response_lower:
    return "Custom vulnerability detected"
```

## Comparison with Standalone Tool

| Feature | Burp Extension | Standalone Tool |
|---------|---------------|-----------------|
| **Integration** | Burp Suite UI | Command line |
| **Workflow** | Right-click scan | Manual curl import |
| **Progress Tracking** | Real-time GUI | Console output |
| **Results Format** | Interactive table | JSON/HTML/XML |
| **Request Capture** | Automatic from Burp | Manual curl copy |
| **Best For** | Active testing | Automated/CI pipelines |

## Security & Ethics

- **Authorized Testing Only**: Only test applications you own or have explicit permission to test
- **Rate Limiting**: Be mindful of server load
- **Data Sensitivity**: Some tests may modify data (mutations)
- **Legal Compliance**: Follow responsible disclosure practices

## Support & Contribution

- **Report Issues**: Open an issue in the GitHub repository
- **Feature Requests**: Suggest new test cases or UI improvements
- **Pull Requests**: Contributions welcome!

## Credits

- **Original Tool**: gqlSweep by 0xs0m
- **Burp Extension**: Based on gqlSweep's testing methodology
- **Burp Suite**: PortSwigger Web Security

## License

Same as the original gqlSweep project. For educational and authorized security testing purposes only.

