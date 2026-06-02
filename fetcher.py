import time
import httpx
from config import MIN_CVSS

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE = "https://api.first.org/data/v1/epss"


def fetch_cves(start, end):
    cves = []
    for severity in ["HIGH", "CRITICAL"]:
        start_index = 0
        results_pp = 2000

        while True:
            params = {
                "pubStartDate": start,
                "pubEndDate": end,
                "cvssV3Severity": severity,
                "resultsPerPage": results_pp,
                "startIndex": start_index,
            }
            response = _get_with_retry(NVD_BASE, params)
            if response is None:
                break

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            cves.extend(vulnerabilities)

            total = data.get("totalResults", 0)
            start_index += results_pp

            if start_index >= total:
                break

            time.sleep(6)

    return cves


def fetch_epss(cve_ids):
    if not cve_ids:
        return {}
    batch_size = 100
    scores = {}

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        params = {"cve": ",".join(batch)}

        response = _get_with_retry(EPSS_BASE, params)
        if response is None:
            continue

        data = response.json()
        for item in data.get("data", []):
            cve_id = item.get("cve")
            epss = item.get("epss")
            if cve_id and epss:
                scores[cve_id] = float(epss)

        time.sleep(1)

    return scores


def _get_with_retry(url, params, max_retries=3):
    wait = 6

    for attempt in range(max_retries):
        try:
            response = httpx.get(url, params=params, timeout=30)
            if response.status_code == 200:
                return response

            if response.status_code in (403, 429):
                retry_after = response.headers.get("Retry-After", wait)
                time.sleep(int(retry_after))
                wait *= 2
                continue

            print(f"Unexpected status {response.status_code} from {url}")
            return None

        except httpx.RequestError as e:
            print(f"Request failed (attempt {attempt + 1}): {e}")
            time.sleep(wait)
            wait *= 2

    print(f"Failed to fetch {url} after {max_retries} attempts")
    return None