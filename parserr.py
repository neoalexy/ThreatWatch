import re
from config import CWE_GROUPS, WATCHED_VENDORS


def parse_cve(raw, epss_scores):
    cve = raw.get("cve", {})
    cve_id = cve.get("id", "unknown")
    published = cve.get("published", "")[:10]
    vuln_status = cve.get("vulnStatus", "unknown")
    description = _get_description(cve)
    score, severity, vector = _get_cvss(cve)
    disputed = _is_disputed(cve)
    vendor, product = _get_vendor(cve, description)
    cwe_group = _get_cwe_group(cve)
    exploitable = _is_easily_exploitable(vector)
    epss = epss_scores.get(cve_id, None)

    return {
        "id": cve_id,
        "published": published,
        "vuln_status": vuln_status,
        "description": description,
        "score": score,
        "severity": severity,
        "vector": vector,
        "disputed": disputed,
        "vendor": vendor,
        "product": product,
        "cwe_group": cwe_group,
        "exploitable": exploitable,
        "epss": epss,
        "watched": vendor in WATCHED_VENDORS,
    }


def _get_description(cve):
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _get_cvss(cve):
    metrics = cve.get("metrics", {})
    v31 = metrics.get("cvssMetricV31", [])

    primary_score = None
    primary_severity = None
    primary_vector = None
    secondary_score = None

    for m in v31:
        data = m.get("cvssData", {})
        if m.get("type") == "Primary":
            primary_score = data.get("baseScore")
            primary_severity = data.get("baseSeverity")
            primary_vector = data.get("vectorString")
        elif m.get("type") == "Secondary" and secondary_score is None:
            secondary_score = data.get("baseScore")

    if primary_score:
        return primary_score, primary_severity, primary_vector
    
    for m in v31:
        data = m.get("cvssData", {})
        return data.get("baseScore"), data.get("baseSeverity"), data.get("vectorString")

    return None, None, None


def _is_disputed(cve):
    metrics = cve.get("metrics", {})
    v31 = metrics.get("cvssMetricV31", [])
    
    primary = None
    secondary = None

    for m in v31:
        score = m.get("cvssData", {}).get("baseScore")
        if m.get("type") == "Primary":
            primary = score
        elif m.get("type") == "Secondary":
            secondary = score

    if primary and secondary:
        return abs(primary - secondary) > 2.0
    return False


PLATFORM_WORDS = {"wordpress", "drupal", "joomla", "magento", "woocommerce"}

def _get_vendor(cve, description):
    #cpe
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) > 4 and parts[3]:
                    vendor = parts[3].lower()
                    product = parts[4].lower() if parts[4] != "*" else None
                    return vendor, product

   #desc
    if description:
        match = re.search(r"The ([A-Za-z0-9_\-\s]+?) plugin for WordPress", description, re.IGNORECASE)
        if match:
            plugin_name = match.group(1).strip().lower().replace(" ", "_")
            return plugin_name, None

    # gen patern
    if description:
        match = re.search(r"vulnerabilit\w+ in ([A-Za-z0-9_\-]+)", description, re.IGNORECASE)
        if not match:
            match = re.search(r"([A-Za-z0-9_\-]+) is vulnerable", description, re.IGNORECASE)
        skip_words = {"the", "a", "an", "this", "that", "some", "unknown",
                      "multiple", "various"} | PLATFORM_WORDS
        if match and match.group(1).lower() not in skip_words:
            return match.group(1).lower(), None

    return "unknown", None


def _get_cwe_group(cve):
    weaknesses = cve.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            cwe_id = desc.get("value", "")
            for group, cwes in CWE_GROUPS.items():
                if cwe_id in cwes:
                    return group
            if cwe_id and cwe_id not in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
                return cwe_id.lower()
    return "no-cwe"

def _is_easily_exploitable(vector):
    if not vector:
        return False
    return "AV:N" in vector and "AC:L" in vector and "PR:N" in vector