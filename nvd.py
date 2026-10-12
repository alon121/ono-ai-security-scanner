"""חיבור למאגר הפרצות הרשמי NVD."""
import re
import time

import requests

import config

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD מגביל ל-50 פניות בחצי דקה עם מפתח, ול-5 בלי מפתח
DELAY_WITH_KEY = 0.8
DELAY_WITHOUT_KEY = 6


def _ask_nvd(params):
    has_key = bool(config.keys["nvd"])
    headers = {"apiKey": config.keys["nvd"]} if has_key else {}

    time.sleep(DELAY_WITH_KEY if has_key else DELAY_WITHOUT_KEY)

    response = requests.get(NVD_URL, params=params, headers=headers, timeout=90)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])


def _severity(cve):
    """מחזיר רמת חומרה וציון CVSS. מעדיף את התקן החדש ביותר שקיים."""
    metrics = cve.get("metrics", {})

    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version)
        if not entries:
            continue

        cvss = entries[0]["cvssData"]
        score = float(cvss.get("baseScore", 0))
        level = cvss.get("baseSeverity")

        if not level:
            if score >= 7:
                level = "HIGH"
            elif score >= 4:
                level = "MEDIUM"
            else:
                level = "LOW"

        return level, score

    return "UNKNOWN", None


def _english_description(cve):
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description["value"]
    return ""


def _weakness_types(cve):
    cwes = set()
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value", "")
            if value.startswith("CWE-"):
                cwes.add(value)
    return sorted(cwes)


def _simplify(cve):
    level, score = _severity(cve)
    published = cve.get("published") or ""

    return {
        "id": cve.get("id"),
        "published": published[:10],
        "severity": level,
        "score": score,
        "cwe": _weakness_types(cve),
        "description": _english_description(cve),
    }


BOUND_SIGNS = {
    "versionStartIncluding": ">=",
    "versionStartExcluding": ">",
    "versionEndIncluding": "<=",
    "versionEndExcluding": "<",
}


def _version_ranges(cve, package_name):
    """
    טווחי הגרסאות המושפעות לפי NVD. כל טווח הוא רשימה של (סימן, גרסה),
    למשל [(">=", "3.0"), ("<", "3.2.5")].
    """
    short = _short_name(package_name).lower()
    ranges = []

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # מבנה ה-CPE: cpe:2.3:a:vendor:product:version:...
                parts = match.get("criteria", "").split(":")
                if not match.get("vulnerable") or len(parts) < 6 or short not in parts[4].lower():
                    continue

                bounds = [(sign, match[key]) for key, sign in BOUND_SIGNS.items() if match.get(key)]
                if not bounds and parts[5] not in ("*", "-"):
                    bounds = [("=", parts[5])]
                if bounds and bounds not in ranges:
                    ranges.append(bounds)

    return ranges


def _affected_versions(cve, package_name):
    """הטווחים כטקסט קריא, למשל ">=3.0 <3.2.5"."""
    ranges = _version_ranges(cve, package_name)
    return [" ".join(sign + version for sign, version in bounds) for bounds in ranges][:8]


def _version_key(version):
    """"2.14.1" -> (2, 14, 1). מספיק כדי להשוות בין רוב הגרסאות."""
    return tuple(int(number) for number in re.findall(r"\d+", version))


def _is_affected(version, ranges):
    """האם הגרסה נמצאת באחד מהטווחים המושפעים."""
    mine = _version_key(version)
    checks = {
        "=": lambda other: mine == other,
        ">=": lambda other: mine >= other,
        ">": lambda other: mine > other,
        "<=": lambda other: mine <= other,
        "<": lambda other: mine < other,
    }
    return any(
        all(checks[sign](_version_key(bound)) for sign, bound in bounds)
        for bounds in ranges
    )


def _short_name(package_name):
    """למשל: "org.apache.logging:log4j" -> "log4j", "github.com/gin-gonic/gin" -> "gin"."""
    return package_name.split(":")[-1].split("/")[-1]


def search_package(name, limit=5):
    """מחזיר את הפרצות החמורות ביותר שקשורות לחבילה."""
    try:
        results = _ask_nvd({"keywordSearch": name, "resultsPerPage": 20})
    except Exception:
        return []

    # NVD מחזיר גם התאמות חלקיות, לכן מסננים לשם החבילה כמילה שלמה
    word = re.compile(rf"\b{re.escape(_short_name(name))}\b", re.IGNORECASE)

    matches = []
    for result in results:
        if word.search(str(result)):
            cve = _simplify(result["cve"])
            cve["affected_versions"] = _affected_versions(result["cve"], name)
            matches.append(cve)

    matches.sort(key=lambda cve: cve["score"] or 0, reverse=True)
    return matches[:limit]


def search_product(name, version="", limit=15):
    """
    בדיקה מעמיקה של מוצר או חבילה בודדת (למשל wordpress).
    מושך הרבה יותר תוצאות מ-search_package, ואם צוינה גרסה - משאיר רק פרצות שבאמת משפיעות עליה.
    """
    results = _ask_nvd({"keywordSearch": name, "resultsPerPage": 2000})

    affected, unknown = [], 0
    for result in results:
        ranges = _version_ranges(result["cve"], name)
        if not ranges:
            # אין טווח גרסאות שמתאים למוצר הזה - כנראה פרצה בתוסף או במוצר אחר עם שם דומה
            unknown += 1
            continue
        if version and not _is_affected(version, ranges):
            continue

        cve = _simplify(result["cve"])
        cve["affected_versions"] = _affected_versions(result["cve"], name)
        affected.append(cve)

    affected.sort(key=lambda cve: (cve["score"] or 0, cve["published"]), reverse=True)
    return {
        "total_results": len(results),
        "matching": len(affected),
        "without_version_data": unknown,
        "cves": affected[:limit],
    }


def get_cve(cve_id):
    try:
        results = _ask_nvd({"cveId": cve_id.upper()})
    except Exception as error:
        return {"error": f"שגיאה בפנייה ל-NVD: {error}"}

    if not results:
        return {"error": f"לא נמצא מידע על {cve_id}"}

    cve = results[0]["cve"]
    details = _simplify(cve)
    details["references"] = [ref.get("url") for ref in cve.get("references", [])[:5]]
    return details
