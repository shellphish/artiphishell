JAVA_CWE_TO_QUERY_ID_MAP = {
    "CWE-020": [
        "java/count-untrusted-data-external-api",
        "java/overly-large-range",
        "java/untrusted-data-to-external-api"
    ],
    "CWE-022": [
        "java/path-injection",
        "java/zipslip"
    ],
    "CWE-023": [
        "java/partial-path-traversal-from-remote",
        "java/partial-path-traversal"
    ],
    "CWE-074": [
        "java/jndi-injection",
        "java/xslt-injection"
    ],
    "CWE-078": [
        "java/relative-path-command",
        "java/exec-tainted-environment",
        "java/command-line-injection",
        "java/concatenated-command-line"
    ],
    "CWE-079": [
        "java/android/webview-addjavascriptinterface",
        "java/android/websettings-javascript-enabled",
        "java/xss"
    ],
    "CWE-089": [
        "java/concatenated-sql-query",
        "java/sql-injection"
    ],
    "CWE-090": [
        "java/ldap-injection"
    ],
    "CWE-094": [
        "java/android/arbitrary-apk-installation",
        "java/groovy-injection",
        "java/insecure-bean-validation",
        "java/jexl-expression-injection",
        "java/mvel-expression-injection",
        "java/spel-expression-injection",
        "java/server-side-template-injection"
    ],
    "CWE-113": [
        "java/netty-http-request-or-response-splitting",
        "java/http-response-splitting"
    ],
    "CWE-117": [
        "java/log-injection"
    ],
    "CWE-129": [
        "java/improper-validation-of-array-construction-code-specified",
        "java/improper-validation-of-array-construction",
        "java/improper-validation-of-array-index-code-specified",
        "java/improper-validation-of-array-index"
    ],
    "CWE-134": [
        "java/tainted-format-string"
    ],
    "CWE-190": [
        "java/tainted-arithmetic",
        "java/uncontrolled-arithmetic",
        "java/extreme-value-arithmetic",
        "java/comparison-with-wider-type"
    ],
    "CWE-200": [
        "java/android/sensitive-notification",
        "java/android/sensitive-text",
        "java/android/websettings-allow-content-access",
        "java/android/websettings-file-access",
        "java/spring-boot-exposed-actuators",
        "java/local-temp-file-or-directory-information-disclosure"
    ],
    "CWE-209": [
        "java/error-message-exposure",
        "java/stack-trace-exposure"
    ],
    "CWE-266": [
        "java/android/intent-uri-permission-manipulation"
    ],
    "CWE-273": [
        "java/unsafe-cert-trust"
    ],
    "CWE-287": [
        "java/android/insecure-local-key-gen",
        "java/android/insecure-local-authentication"
    ],
    "CWE-295": [
        "java/android/missing-certificate-pinning",
        "java/improper-webview-certificate-validation",
        "java/insecure-trustmanager"
    ],
    "CWE-297": [
        "java/insecure-smtp-ssl",
        "java/unsafe-hostname-verification"
    ],
    "CWE-312": [
        "java/android/backup-enabled",
        "java/android/cleartext-storage-database",
        "java/android/cleartext-storage-filesystem",
        "java/cleartext-storage-in-class",
        "java/cleartext-storage-in-cookie",
        "java/cleartext-storage-in-properties",
        "java/android/cleartext-storage-shared-prefs"
    ],
    "CWE-319": [
        "java/non-https-url",
        "java/non-ssl-connection",
        "java/non-ssl-socket-factory"
    ],
    "CWE-326": [
        "java/insufficient-key-size"
    ],
    "CWE-327": [
        "java/weak-cryptographic-algorithm",
        "java/potentially-weak-cryptographic-algorithm"
    ],
    "CWE-330": [
        "java/insecure-randomness"
    ],
    "CWE-335": [
        "java/predictable-seed"
    ],
    "CWE-338": [
        "java/jhipster-prng"
    ],
    "CWE-347": [
        "java/missing-jwt-signature-check"
    ],
    "CWE-352": [
        "java/csrf-unprotected-request-type",
        "java/spring-disabled-csrf-protection"
    ],
    "CWE-367": [
        "java/toctou-race-condition"
    ],
    "CWE-421": [
        "java/socket-auth-race-condition"
    ],
    "CWE-441": [
        "java/android/unsafe-content-uri-resolution"
    ],
    "CWE-470": [
        "java/android/fragment-injection-preference-activity",
        "java/android/fragment-injection"
    ],
    "CWE-489": [
        "java/android/debuggable-attribute-enabled",
        "java/android/webview-debugging-enabled"
    ],
    "CWE-501": [
        "java/trust-boundary-violation"
    ],
    "CWE-502": [
        "java/unsafe-deserialization"
    ],
    "CWE-522": [
        "java/insecure-basic-auth",
        "java/insecure-ldap-auth"
    ],
    "CWE-524": [
        "java/android/sensitive-keyboard-cache"
    ],
    "CWE-532": [
        "java/sensitive-log"
    ],
    "CWE-552": [
        "java/unvalidated-url-forward"
    ],
    "CWE-601": [
        "java/unvalidated-url-redirection"
    ],
    "CWE-611": [
        "java/xxe"
    ],
    "CWE-614": [
        "java/insecure-cookie"
    ],
    "CWE-643": [
        "java/xml/xpath-injection"
    ],
    "CWE-676": [
        "java/potentially-dangerous-function"
    ],
    "CWE-681": [
        "java/tainted-numeric-cast"
    ],
    "CWE-730": [
        "java/polynomial-redos",
        "java/redos",
        "java/regex-injection"
    ],
    "CWE-732": [
        "java/world-writable-file-read"
    ],
    "CWE-749": [
        "java/android/unsafe-android-webview-fetch"
    ],
    "CWE-780": [
        "java/rsa-without-oaep"
    ],
    "CWE-798": [
        "java/hardcoded-credential-api-call",
        "java/hardcoded-credential-comparison",
        "java/hardcoded-credential-sensitive-call",
        "java/hardcoded-password-field"
    ],
    "CWE-807": [
        "java/user-controlled-bypass",
        "java/tainted-permissions-check"
    ],
    "CWE-829": [
        "java/maven/non-https-url"
    ],
    "CWE-833": [
        "java/lock-order-inconsistency"
    ],
    "CWE-835": [
        "java/unreachable-exit-in-loop"
    ],
    "CWE-917": [
        "java/ognl-injection"
    ],
    "CWE-918": [
        "java/ssrf"
    ],
    "CWE-925": [
        "java/improper-intent-verification"
    ],
    "CWE-926": [
        "java/android/incomplete-provider-permissions",
        "java/android/implicitly-exported-component"
    ],
    "CWE-927": [
        "java/android/implicit-pendingintents",
        "java/android/sensitive-communication",
        "java/android/sensitive-result-receiver"
    ],
    "CWE-940": [
        "java/android/intent-redirection"
    ],
    "CWE-1104": [
        "java/maven/dependency-upon-bintray"
    ],
    "CWE-1204": [
        "java/static-initialization-vector"
    ]
}

C_CWE_TO_QUERY_ID_MAP = {
    "CWE-014": [
        "cpp/memset-may-be-deleted"
    ],
    "CWE-020": [
        "cpp/count-untrusted-data-external-api",
        "cpp/count-untrusted-data-external-api-ir",
        "cpp/untrusted-data-to-external-api-ir",
        "cpp/untrusted-data-to-external-api"
    ],
    "CWE-022": [
        "cpp/path-injection"
    ],
    "CWE-078": [
        "cpp/command-line-injection"
    ],
    "CWE-079": [
        "cpp/cgi-xss"
    ],
    "CWE-089": [
        "cpp/sql-injection"
    ],
    "CWE-114": [
        "cpp/uncontrolled-process-operation"
    ],
    "CWE-119": [
        "cpp/overflow-buffer",
        "cpp/overrun-write"
    ],
    "CWE-120": [
        "cpp/badly-bounded-write",
        "cpp/overrunning-write-with-float",
        "cpp/overrunning-write",
        "cpp/unbounded-write",
        "cpp/very-likely-overrunning-write"
    ],
    "CWE-121": [
        "cpp/unterminated-variadic-call"
    ],
    "CWE-129": [
        "cpp/unclear-array-index-validation"
    ],
    "CWE-131": [
        "cpp/no-space-for-terminator"
    ],
    "CWE-134": [
        "cpp/tainted-format-string"
    ],
    "CWE-170": [
        "cpp/user-controlled-null-termination-tainted"
    ],
    "CWE-190": [
        "cpp/tainted-arithmetic",
        "cpp/uncontrolled-arithmetic",
        "cpp/arithmetic-with-extreme-values",
        "cpp/comparison-with-wider-type",
        "cpp/integer-overflow-tainted",
        "cpp/uncontrolled-allocation-size"
    ],
    "CWE-191": [
        "cpp/unsigned-difference-expression-compared-zero"
    ],
    "CWE-193": [
        "cpp/invalid-pointer-deref"
    ],
    "CWE-253": [
        "cpp/hresult-boolean-conversion"
    ],
    "CWE-290": [
        "cpp/user-controlled-bypass"
    ],
    "CWE-295": [
        "cpp/certificate-result-conflation",
        "cpp/certificate-not-checked"
    ],
    "CWE-311": [
        "cpp/cleartext-storage-buffer",
        "cpp/cleartext-storage-file",
        "cpp/cleartext-transmission"
    ],
    "CWE-313": [
        "cpp/cleartext-storage-database"
    ],
    "CWE-319": [
        "cpp/non-https-url"
    ],
    "CWE-326": [
        "cpp/insufficient-key-size"
    ],
    "CWE-327": [
        "cpp/weak-cryptographic-algorithm",
        "cpp/openssl-heartbleed"
    ],
    "CWE-367": [
        "cpp/toctou-race-condition"
    ],
    "CWE-416": [
        "cpp/iterator-to-expired-container",
        "cpp/use-of-string-after-lifetime-ends",
        "cpp/use-of-unique-pointer-after-lifetime-ends"
    ],
    "CWE-428": [
        "cpp/unsafe-create-process-call"
    ],
    "CWE-457": [
        "cpp/conditionally-uninitialized-variable"
    ],
    "CWE-468": [
        "cpp/incorrect-pointer-scaling-char",
        "cpp/suspicious-pointer-scaling",
        "cpp/suspicious-pointer-scaling-void",
        "cpp/suspicious-add-sizeof"
    ],
    "CWE-497": [
        "cpp/system-data-exposure",
        "cpp/potential-system-data-exposure"
    ],
    "CWE-570": [
        "cpp/incorrect-allocation-error-handling"
    ],
    "CWE-611": [
        "cpp/external-entity-expansion"
    ],
    "CWE-676": [
        "cpp/dangerous-function-overflow",
        "cpp/dangerous-cin",
        "cpp/potentially-dangerous-function"
    ],
    "CWE-704": [
        "cpp/incorrect-string-type-conversion"
    ],
    "CWE-732": [
        "cpp/world-writable-file-creation",
        "cpp/open-call-with-mode-argument",
        "cpp/unsafe-dacl-security-descriptor"
    ],
    "CWE-764": [
        "cpp/lock-order-cycle",
        "cpp/twice-locked",
        "cpp/unreleased-lock"
    ],
    "CWE-807": [
        "cpp/tainted-permissions-check"
    ],
    "CWE-835": [
        "cpp/infinite-loop-with-unsatisfiable-exit-condition"
    ],
    "CWE-843": [
        "cpp/type-confusion"
    ]
}

JAVA_CWE_LIST = [
    "CWE-022",
    "CWE-023",
    "CWE-074",
    "CWE-078",
    "CWE-089",
    "CWE-090",
    "CWE-094",
    # "CWE-434", # In experimental/Security/CWE/
    "CWE-470",
    "CWE-502",
    "CWE-643",
    "CWE-917",
    "CWE-918",
]


C_CWE_LIST = [
    "CWE-119",
    "CWE-121",
    # "CWE-122", # Not existing in codeql
    # "CWE-125", # In experimental/Security/CWE/
    "CWE-190",
    # "CWE-400", # Not existing in codeql
    # "CWE-415", # In experimental/Security/CWE/
    "CWE-416",
    # "CWE-476", # In experimental/Security/CWE/
    # "CWE-506", # Not existing in codeql
    # "CWE-787" # In experimental/Security/CWE/
]

VULN_TYPE_MAP = {
    # Java
    "CWE-022": "path-traversal",
    "CWE-023": "path-traversal",
    "CWE-074": "injection",
    "CWE-078": "os-command-injection",
    "CWE-089": "sql-injection",
    "CWE-090": "ldap-injection",
    "CWE-094": "script-engine-injection",
    "CWE-434": "unrestricted-file-upload",
    "CWE-470": "reflection",
    "CWE-502": "deserialization",
    "CWE-643": "xpath-injection",
    "CWE-664": "resource-lifecycle",
    "CWE-691": "codegen-control",
    "CWE-707": "improper-neutralization",
    "CWE-913": "dynamic-code-control",
    "CWE-917": "expression-language-injection",
    "CWE-918": "ssrf",
    # C
    "CWE-119": "buffer-overflow",
    "CWE-121": "stack-buffer-overflow",
    "CWE-122": "heap-buffer-overflow",
    "CWE-125": "out-of-bounds-read",
    "CWE-190": "integer-overflow",
    "CWE-400": "resource-exhaustion",
    "CWE-415": "double-free",
    "CWE-416": "use-after-free",
    "CWE-476": "null-pointer-dereference",
    "CWE-506": "malicious-code",
    "CWE-787": "out-of-bounds-write",
}