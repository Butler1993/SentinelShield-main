import re

# Define attack categories
CAT_SQLI = "SQL Injection"
CAT_XSS = "Cross-Site Scripting (XSS)"
CAT_LFI = "Local File Inclusion"
CAT_TRAVERSAL = "Directory Traversal"
CAT_CMD_INJ = "Command Injection"

# Signature dictionary
# Format: List of dictionaries with 'name', 'pattern' (regex), 'category'
SIGNATURES = [
    # --- SQL Injection ---
    {
        'name': 'Union Select',
        'pattern': re.compile(r'union\s+select', re.IGNORECASE),
        'category': CAT_SQLI
    },
    {
        'name': 'Generic OR SQLi',
        'pattern': re.compile(r"'\s+or\s+'\d+'\s*=\s*'\d+", re.IGNORECASE),
        'category': CAT_SQLI
    },
    {
        'name': 'SQL Comment --',
        'pattern': re.compile(r'--\s', re.IGNORECASE),
        'category': CAT_SQLI
    },
    {
        'name': 'SQL Comment #',
        'pattern': re.compile(r'#', re.IGNORECASE),
        'category': CAT_SQLI
    },
    {
        'name': 'Sleep Command',
        'pattern': re.compile(r'sleep\(\d+\)', re.IGNORECASE),
        'category': CAT_SQLI
    },

    # --- XSS ---
    {
        'name': 'Script Tag',
        'pattern': re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL),
        'category': CAT_XSS
    },
    {
        'name': 'OnEvent Attribute',
        'pattern': re.compile(r'on\w+\s*=', re.IGNORECASE),
        'category': CAT_XSS
    },
    {
        'name': 'Javascript Protocol',
        'pattern': re.compile(r'javascript:', re.IGNORECASE),
        'category': CAT_XSS
    },

    # --- Directory Traversal / LFI ---
    {
        'name': 'Parent Directory ..',
        'pattern': re.compile(r'\.\./', re.IGNORECASE),
        'category': CAT_TRAVERSAL
    },
    {
        'name': 'LFI - etc/passwd',
        'pattern': re.compile(r'/etc/passwd', re.IGNORECASE),
        'category': CAT_LFI
    },
    {
        'name': 'LFI - Windows INI',
        'pattern': re.compile(r'boot\.ini', re.IGNORECASE),
        'category': CAT_LFI
    },

    # --- Command Injection ---
    {
        'name': 'System Pipe',
        'pattern': re.compile(r'\|', re.IGNORECASE),
        'category': CAT_CMD_INJ
    },
    {
        'name': 'System Semicolon',
        'pattern': re.compile(r';\s*(ls|cat|pwd|whoami|net|mkdir|rm)', re.IGNORECASE),
        'category': CAT_CMD_INJ
    },
    {
        'name': 'Chain Operator',
        'pattern': re.compile(r'&&', re.IGNORECASE),
        'category': CAT_CMD_INJ
    }
]
