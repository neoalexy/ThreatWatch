from collections import Counter
from config import WATCHED_VENDORS
from config import CWE_GROUPS, WATCHED_VENDORS, SAAS_SIGNALS


def analyze(cves_current, cves_previous):
    severity_count = _count_by_severity(cves_current)
    top_vendors = _top_vendors(cves_current)
    top10 = _top10_scoring(cves_current)
    exploitable = _easily_exploitable(cves_current)
    watched_alerts = _watched_vendor_alerts(cves_current)
    trends = _vendor_trends(cves_current, cves_previous)
    coefficients = _vendor_exploitability_coefficient(cves_current)
    emerging = _pre_emerging_threats(cves_current)
    
    top_vendor_names = [v[0] for v in top_vendors]
    product_breakdown = _vendor_product_breakdown(cves_current, top_vendor_names)

    return {
        "total": len(cves_current),
        "severity_count": severity_count,
        "top_vendors": top_vendors,
        "top10": top10,
        "exploitable": exploitable,
        "watched_alerts": watched_alerts,
        "trends": trends,
        "coefficients": coefficients,
        "emerging": emerging,
        "product_breakdown": product_breakdown,
    }


def _count_by_severity(cves):
    counts = Counter()
    for cve in cves:
        severity = cve.get("severity") or "UNKNOWN"
        counts[severity] += 1
    return dict(counts)


def _top_vendors(cves, n=5):
    counts = Counter()
    for cve in cves:
        vendor = cve.get("vendor", "unknown")
        if vendor != "unknown":
            counts[vendor] += 1
    return counts.most_common(n)


def _top10_scoring(cves):
    with_score = [c for c in cves if c.get("score") is not None and c.get("vendor") != "unknown"]
    sorted_cves = sorted(with_score, key=lambda c: c["score"], reverse=True)
    return sorted_cves[:10]


def _easily_exploitable(cves):
    exploitable = [c for c in cves if c.get("exploitable")]
    exploitable.sort(key=lambda c: (c.get("epss") or 0), reverse=True)
    return exploitable[:10]


def _watched_vendor_alerts(cves):
    alerts = {}
    for cve in cves:
        vendor = cve.get("vendor", "unknown")
        if vendor in WATCHED_VENDORS:
            if vendor not in alerts:
                alerts[vendor] = {
                    "count": 0,
                    "max_score": 0,
                    "max_epss": 0,
                    "cwe_groups": Counter(),
                }
            alerts[vendor]["count"] += 1
            score = cve.get("score") or 0
            epss = cve.get("epss") or 0
            if score > alerts[vendor]["max_score"]:
                alerts[vendor]["max_score"] = score
            if epss > alerts[vendor]["max_epss"]:
                alerts[vendor]["max_epss"] = epss
            group = cve.get("cwe_group", "other")
            alerts[vendor]["cwe_groups"][group] += 1

    for vendor in alerts:
        groups = alerts[vendor]["cwe_groups"]
        if groups:
            alerts[vendor]["dominant_attack"] = groups.most_common(1)[0][0]
        else:
            alerts[vendor]["dominant_attack"] = "unknown"
        del alerts[vendor]["cwe_groups"]

    return alerts


def _vendor_trends(cves_current, cves_previous):
    current_counts = Counter(c.get("vendor", "unknown") for c in cves_current)
    previous_counts = Counter(c.get("vendor", "unknown") for c in cves_previous)

    trends = {}
    all_vendors = set(current_counts.keys()) | set(previous_counts.keys())

    for vendor in all_vendors:
        if vendor == "unknown":
            continue
        curr = current_counts.get(vendor, 0)
        prev = previous_counts.get(vendor, 0)

        if prev == 0:
            trend = "new"
        else:
            change = ((curr - prev) / prev) * 100
            if change > 20:
                trend = f"↑ +{int(change)}%"
            elif change < -20:
                trend = f"↓ {int(change)}%"
            else:
                trend = "→ stable"

        trends[vendor] = {"current": curr, "previous": prev, "trend": trend}

    return trends

def _vendor_exploitability_coefficient(cves):
    by_vendor = {}
    for cve in cves:
        vendor = cve.get("vendor", "unknown")
        if vendor == "unknown":
            continue
        if vendor not in by_vendor:
            by_vendor[vendor] = []
        by_vendor[vendor].append(cve)

    coefficients = []
    for vendor, vcves in by_vendor.items():
        epss_values = [c["epss"] for c in vcves if c.get("epss") is not None]
        if not epss_values:
            continue
        avg_epss = sum(epss_values) / len(epss_values)
        coeff = round(len(vcves) * avg_epss * 100, 1)
        coefficients.append({
            "vendor": vendor,
            "cve_count": len(vcves),
            "avg_epss": round(avg_epss * 100, 1),
            "coefficient": coeff,
            "risk_label": _risk_label(coeff)
})

    return sorted(coefficients, key=lambda x: x["coefficient"], reverse=True)[:8]

def _risk_label(coeff):
    if coeff > 40:
        return "HIGH ACTIVE RISK"
    elif coeff > 15:
        return "MODERATE RISK"
    else:
        return "low exploitation"
    
def _get_saas_tag(description):
    desc = description.lower()
    for tag, keywords in SAAS_SIGNALS.items():
        if any(kw in desc for kw in keywords):
            return tag
    return None


def _pre_emerging_threats(cves, epss_threshold=0.15):
    big_vendors = {"microsoft", "google", "oracle", "adobe", "apple", "cisco", "linux", "wordpress"}

    emerging = []
    for cve in cves:
        epss = cve.get("epss")
        vendor = cve.get("vendor", "unknown")
        score = cve.get("score") or 0

        if epss and epss >= epss_threshold and vendor not in big_vendors and score >= 7.0:
            tag = _get_saas_tag(cve.get("description", ""))
            cve["saas_tag"] = tag
            emerging.append(cve)

    return sorted(emerging, key=lambda x: x.get("epss", 0), reverse=True)[:5]

def _vendor_product_breakdown(cves, vendors, top_n=5):
    breakdown = {}
    for cve in cves:
        vendor = cve.get("vendor", "unknown")
        if vendor not in vendors:
            continue
        product = cve.get("product") or "unknown"
        if vendor not in breakdown:
            breakdown[vendor] = {}
        if product not in breakdown[vendor]:
            breakdown[vendor][product] = 0
        breakdown[vendor][product] += 1

    result = {}
    for vendor, products in breakdown.items():
        sorted_products = sorted(products.items(), key=lambda x: x[1], reverse=True)
        result[vendor] = sorted_products[:top_n]

    return result