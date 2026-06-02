from datetime import datetime, timedelta

DAYS_BACK = 30
MIN_CVSS = 7.0

WATCHED_VENDORS = [
    "google",
    "microsoft",
    "okta",
    "github", 
    "slack",
    "salesforce",
]

CWE_GROUPS = {
    "auth_bypass": [
        "CWE-287", "CWE-285", "CWE-306", "CWE-266", "CWE-269",
        "CWE-284", "CWE-288", "CWE-290", "CWE-294", "CWE-302",
        "CWE-303", "CWE-304", "CWE-305", "CWE-307", "CWE-308",
        "CWE-345", "CWE-346", "CWE-349", 
    ],
    "injection": [
        "CWE-89", "CWE-79", "CWE-77", "CWE-74", "CWE-94",
        "CWE-78", "CWE-917", "CWE-1336", "CWE-80", "CWE-83",
        "CWE-116", "CWE-643", "CWE-91",
    ],
    "data_exposure": [
        "CWE-200", "CWE-312", "CWE-319", "CWE-359", "CWE-538",
        "CWE-540", "CWE-548", "CWE-209", "CWE-213", "CWE-214",
    ],
    "memory": [
        "CWE-125", "CWE-787", "CWE-416", "CWE-476", "CWE-119",
        "CWE-120", "CWE-122", "CWE-123", "CWE-124", "CWE-126",
        "CWE-127", "CWE-415", "CWE-590", "CWE-762",
    ],
    "access_control": [
        "CWE-22", "CWE-434", "CWE-862", "CWE-863", "CWE-639",
        "CWE-640", "CWE-641", "CWE-642", "CWE-644", "CWE-645",
    ],
    "rce": [
        "CWE-502", "CWE-470", "CWE-95", "CWE-96", "CWE-97",
        "CWE-98", "CWE-99",
    ],
    "input_val": [
        "CWE-20", "CWE-1284", "CWE-129", "CWE-131", 
    ],
}

def get_date_range(days_back=DAYS_BACK):
    end = datetime.utcnow()
    start = end - timedelta(days=days_back)
    fmt = "%Y-%m-%dT00:00:00.000"
    return start.strftime(fmt), end.strftime(fmt)

SAAS_SIGNALS = {
    "OAuth/token abuse vector": ["oauth", "token", "jwt", "bearer", "refresh token"],
    "API attack surface": ["api", "webhook", "rest", "graphql", "endpoint"],
    "AI/LLM infrastructure risk": ["llm", "ai agent", "openai", "anthropic", "langchain", "litellm"],
    "Supply chain risk": ["dependency", "package", "npm", "pypi", "ci/cd", "pipeline", "github action","monorepo", "build tool", "nx", "webpack", "vite", "gradle", "maven"],
    "Cloud/storage exposure": ["s3", "azure", "aws", "bucket", "cloud", "misconfiguration"],
    "Identity/SSO risk": ["saml", "sso", "identity", "ldap", "active directory"],
}