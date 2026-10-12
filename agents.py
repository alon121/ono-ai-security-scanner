"""
הסוכנים של המערכת:
PackageScannerAgent - בודק כל חבילה מול NVD, ואז Claude בודק את הגרסאות ומחפש סיכונים נוספים
CVEAnalystAgent     - כותב דו"ח מתועדף (Claude) ומאמת אותו (ChatGPT)
AdvisorAgent        - יועץ אבטחה בצ'אט
Coordinator         - מנתב כל בקשה לסוכן המתאים

כל פעולה מקבלת פונקציית log, שדרכה הסוכנים מדווחים לקונסולה בממשק מה הם עושים.
"""
import json
import re
import time
from pathlib import Path

import config
import github
import llm
import nvd
import parsers

BASE_RULES = """אתה חלק ממערכת Multi-Agent לאבטחת שרשרת אספקת תוכנה.
ענה בעברית, בצורה תמציתית ומעשית.
אל תמציא מזהי CVE, גרסאות או עובדות שלא נמסרו לך.
אם המידע חסר - אמור זאת במפורש."""


def no_log(text, kind="info"):
    pass


def to_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2)


def call_model(log, model_name, ask, role, prompt):
    """מפעיל מודל ומדווח לקונסולה כמה זמן זה לקח והאם הצליח."""
    started = time.time()
    answer = ask(role, prompt)
    seconds = time.time() - started

    if answer.startswith("שגיא"):
        log(f"{model_name} נכשל: {answer}", "error")
    else:
        log(f"{model_name} סיים תוך {seconds:.1f} שניות ({len(answer)} תווים)", "ok")
    return answer


class PackageScannerAgent:
    REVIEW_ROLE = BASE_RULES + """

התפקיד שלך: בודק חבילות. עבור על כל החבילות ברשימה ובדוק:
1. לכל פרצה מ-NVD: האם הגרסה שבשימוש נמצאת בטווח affected_versions.
   אם היא מחוץ לטווח - זו התראת שווא. אם הטווח חסר - כתוב שצריך בדיקה ידנית.
2. האם ה-CVE באמת שייך לחבילה הזאת, ולא לתוכנה אחרת עם שם דומה.
3. סיכונים שלא מופיעים ב-NVD ושאתה מכיר בוודאות: חבילה שהוצאה משימוש או לא מתוחזקת,
   שם שנראה כמו התחזות לחבילה מוכרת (typosquatting), או גרסה ישנה מאוד.
   סמן כל ממצא כזה במילים "(מידע המודל)", כי הוא לא מאומת ב-NVD.
4. חבילה בלי גרסה מוצמדת ("לא צוין") - סיכון לשרשרת האספקה.

החזר טבלה: חבילה | גרסה | מצב (פגיע / התראת שווא / דורש בדיקה / סיכון אחר) | הסבר קצר.
כלול בטבלה רק חבילות שיש להן ממצא, ובסוף כתוב כמה חבילות נבדקו ונמצאו תקינות."""

    def check(self, packages, log=no_log):
        """בודק כל חבילה ב-NVD. מחזיר רק את החבילות שנמצאו להן פרצות."""
        log(f"סורק החבילות: מתחיל לבדוק {len(packages)} חבילות", "agent")

        cves_by_name = {}
        findings = []
        for number, package in enumerate(packages, start=1):
            name = package["name"]
            log(f"[{number}/{len(packages)}] בודק ב-NVD: {name} {package['version']}", "nvd")

            # אותה חבילה בכמה גרסאות או בכמה קבצים - פונים ל-NVD פעם אחת
            if name.lower() not in cves_by_name:
                cves_by_name[name.lower()] = nvd.search_package(name)
            cves = cves_by_name[name.lower()]

            if cves:
                worst = cves[0]
                log(f"      נמצאו {len(cves)} פרצות. החמורה: {worst['id']} (CVSS {worst['score']})", "warn")
                findings.append({**package, "cves": cves})
            else:
                log("      לא נמצאו פרצות", "ok")

        return findings

    def check_product(self, name, version, log=no_log):
        """בדיקה מעמיקה של מוצר או חבילה אחת. מחזיר את החבילה ואת הממצאים עליה."""
        shown_version = version or "לא צוין"
        log(f"סורק החבילות: בדיקה מעמיקה של {name} {shown_version}", "agent")
        log(f"בודק ב-NVD את כל הפרצות שמוזכר בהן {name}", "nvd")

        result = nvd.search_product(name, version)
        log(f"      התקבלו {result['total_results']} תוצאות מ-NVD", "nvd")
        if version:
            log(f"      {result['matching']} פרצות משפיעות על גרסה {version} לפי טווחי הגרסאות", "warn" if result["matching"] else "ok")
        else:
            log(f"      {result['matching']} פרצות שייכות למוצר. לא צוינה גרסה, לכן אי אפשר לסנן לפי גרסה", "warn")
        if result["without_version_data"]:
            log(f"      {result['without_version_data']} תוצאות סוננו: בלי נתוני גרסה למוצר הזה (למשל תוספים)")

        package = {"name": name, "version": shown_version, "ecosystem": "מוצר / חבילה"}
        findings = []
        if result["cves"]:
            findings.append({
                **package,
                "cves": result["cves"],
                "nvd_summary": {
                    "תוצאות_ב-NVD": result["total_results"],
                    "פרצות_תואמות": result["matching"],
                    "מוצגות": len(result["cves"]),
                },
            })
        return [package], findings

    def review(self, packages, findings, log=no_log):
        """Claude עובר על כל החבילות: מאמת את התאמת הגרסאות ומחפש סיכונים מחוץ ל-NVD."""
        log(f"סורק החבילות: מפעיל את Claude ({config.models['claude']}) לבדיקת החבילות", "ai")
        log("Claude בודק אם הגרסאות באמת פגיעות, ומחפש חבילות נטושות, התחזויות וגרסאות לא מוצמדות", "ai")

        prompt = "בדוק את החבילות הבאות:\n" + to_json({
            "חבילות": packages,
            "פרצות_מ-NVD": findings,
        })
        return call_model(log, "Claude", llm.ask_claude, self.REVIEW_ROLE, prompt)


class CVEAnalystAgent:
    REPORT_ROLE = BASE_RULES + """

התפקיד שלך: לבנות דו"ח אבטחה מתועדף.
מבנה הדו"ח:
1. שורה תחתונה - רמת הסיכון הכוללת של הפרויקט (קריטי / גבוה / בינוני / נמוך) ומשפט הסבר.
2. דורש טיפול מיידי - לכל פריט: שם החבילה והגרסה, מזהה CVE, ציון CVSS,
   למה זה חמור דווקא בהקשר של הפרויקט הזה, ולאיזו גרסה לעדכן.
3. לטיפול בהמשך - פרצות אמיתיות בעלות עדיפות נמוכה יותר.
4. אפשר להתעלם - פרצות שלא רלוונטיות לשימוש של הפרויקט, עם הסבר קצר למה.
5. סיכונים נוספים - ממצאים מבדיקת החבילות שלא מופיעים ב-NVD (חבילות נטושות, התחזויות, גרסאות לא מוצמדות).
6. צעדי ביצוע - פקודות עדכון קונקרטיות.

תקבל גם את בדיקת החבילות שבוצעה קודם. התבסס עליה:
פרצה שסומנה כהתראת שווא כי הגרסה מחוץ לטווח המושפע - שים בסעיף 4.
אם החבילות הגיעו מכמה קבצים, ציין לכל פריט מאיזה קובץ (השדה file)."""

    VALIDATOR_ROLE = BASE_RULES + """

התפקיד שלך: לאמת דו"ח אבטחה שנכתב על ידי מודל אחר, מול נתוני ה-NVD הגולמיים ובדיקת החבילות.
החזר עד 5 נקודות בלבד:
- אי דיוקים או קביעות שאינן נתמכות בנתונים
- פרצות חמורות שהדו"ח פספס
- גרסה שסומנה כבטוחה או כפגיעה בטעות, לפי affected_versions
- תעדוף שלדעתך שגוי
אם הדו"ח מדויק, כתוב: "הדו\"ח אומת ללא הערות מהותיות"."""

    def report(self, packages, findings, review, source, project_context, log=no_log):
        """Claude כותב את הדו"ח, ו-ChatGPT בודק אותו מול הנתונים המקוריים."""
        scan_data = to_json({
            "מקור": source,
            "חבילות_שנסרקו": packages,
            "פרצות_מ-NVD": findings,
        })

        report_prompt = f"""הקשר הפרויקט מהמשתמש: {project_context or "לא נמסר"}

נתוני הסריקה:
{scan_data}

בדיקת החבילות:
{review}

בנה את הדו"ח המתועדף."""

        log(f"אנליסט ה-CVE: מפעיל את Claude ({config.models['claude']})", "ai")
        log("Claude מתעדף את הממצאים לפי הקשר הפרויקט וכותב דו\"ח", "ai")
        report = call_model(log, "Claude", llm.ask_claude, self.REPORT_ROLE, report_prompt)

        if not llm.has_gpt():
            log("אין מפתח OpenAI - מדלג על האימות המוצלב", "warn")
            return report, "אימות מוצלב לא בוצע: לא הוגדר OPENAI_API_KEY."

        log(f"אנליסט ה-CVE: מפעיל את ChatGPT ({config.models['gpt']}) לאימות מוצלב", "ai")
        log("ChatGPT משווה את הדו\"ח לנתוני NVD ומחפש אי דיוקים ופרצות שפוספסו", "ai")
        validation_prompt = (
            f"נתוני NVD גולמיים:\n{scan_data}\n\n"
            f"בדיקת החבילות:\n{review}\n\n"
            f"הדו\"ח לאימות:\n{report}"
        )
        validation = call_model(log, "ChatGPT", llm.ask_gpt, self.VALIDATOR_ROLE, validation_prompt)

        return report, validation

    def analyze_single(self, cve_id, log=no_log):
        log(f"בודק ב-NVD: {cve_id}", "nvd")
        cve_data = nvd.get_cve(cve_id)
        if "error" in cve_data:
            log(cve_data["error"], "error")
            return cve_data["error"]

        log(f"אנליסט ה-CVE: מפעיל את Claude ({config.models['claude']}) לניתוח הפרצה", "ai")
        prompt = (
            "נתח את הפרצה הבאה: מה ההשפעה, מי מושפע, מה רמת הדחיפות ומה לעשות.\n"
            + to_json(cve_data)
        )
        return call_model(log, "Claude", llm.ask_claude, self.REPORT_ROLE, prompt)


class AdvisorAgent:
    ROLE = BASE_RULES + """

התפקיד שלך: יועץ אבטחה בשיחה חופשית.
אתה עונה על שאלות אבטחה, מסביר פרצות ספציפיות,
וממליץ על חבילות חלופיות מתוחזקות לחבילות לא מאובטחות.
כשאתה ממליץ על חלופה, ציין גם מה עלות המעבר."""

    CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"

    def __init__(self):
        self.history = []

    def chat(self, message, log=no_log):
        """עונה על שאלה. אם הוזכר בה CVE, מצרף את הנתונים עליו מ-NVD."""
        nvd_context = self._fetch_mentioned_cves(message, log)

        question = f"שאלת המשתמש: {message}"
        if nvd_context:
            prompt = nvd_context + "\n\n" + question
        else:
            prompt = question

        log(f"יועץ האבטחה: מפעיל את Claude ({config.models['claude']}) כדי לענות", "ai")
        answer = call_model(log, "Claude", llm.ask_claude, self.ROLE, prompt)

        self.history.append({"role": "user", "content": message})
        self.history.append({"role": "assistant", "content": answer})
        return answer

    def _fetch_mentioned_cves(self, message, log):
        cve_ids = set(re.findall(self.CVE_PATTERN, message, re.IGNORECASE))
        if not cve_ids:
            log("לא הוזכר CVE בשאלה - עונה מהידע הכללי של המודל")

        context = ""
        for cve_id in cve_ids:
            log(f"זוהה {cve_id.upper()} בשאלה - שולף נתונים אמיתיים מ-NVD", "nvd")
            cve_data = nvd.get_cve(cve_id)
            context += f"\nנתוני NVD עבור {cve_id.upper()}:\n"
            context += json.dumps(cve_data, ensure_ascii=False)
        return context

    def second_opinion(self, message):
        if not llm.has_gpt():
            return "לא הוגדר OPENAI_API_KEY - אין דעה שנייה."
        return llm.ask_gpt(self.ROLE, message)

    def reset(self):
        self.history = []


class Coordinator:
    def __init__(self):
        self.scanner = PackageScannerAgent()
        self.analyst = CVEAnalystAgent()
        self.advisor = AdvisorAgent()

    def scan_packages(self, packages, source, project_context="", log=no_log):
        """
        תהליך הסריקה המלא: NVD -> בדיקת Claude -> דו"ח Claude -> אימות ChatGPT.
        מחזיר סיכום קצר, דו"ח, ואימות מוצלב.
        """
        if not packages:
            log("לא זוהו חבילות", "error")
            return "לא זוהו חבילות לסריקה.", "", ""

        log(f"המתאם: {len(packages)} חבילות מתוך {source} - מעביר לסורק החבילות", "agent")
        findings = self.scanner.check(packages, log)
        return self._analyze(packages, findings, source, project_context, log)

    def scan_product(self, name, version="", project_context="", log=no_log):
        """בדיקה של מוצר או חבילה בודדת, למשל wordpress 6.2."""
        name, version = name.strip(), version.strip()
        if not name:
            raise ValueError("כתבו שם של חבילה או מוצר לבדיקה")

        log(f"המתאם: התבקשה בדיקה של {name} - מעביר לסורק החבילות", "agent")
        packages, findings = self.scanner.check_product(name, version, log)
        source = f"{name} {version}".strip()
        return self._analyze(packages, findings, source, project_context, log)

    def _analyze(self, packages, findings, source, project_context, log):
        """החלק המשותף לכל סוגי הסריקה: בדיקת Claude, דו"ח Claude ואימות ChatGPT."""
        review = self.scanner.review(packages, findings, log)

        log(f"המתאם: נמצאו פרצות ב-{len(findings)} חבילות - מעביר לאנליסט ה-CVE", "agent")
        report, validation = self.analyst.report(
            packages, findings, review, source, project_context, log
        )

        log("הסריקה הסתיימה", "done")
        if len(packages) == 1:
            cve_count = len(findings[0]["cves"]) if findings else 0
            summary = f"נבדק {source}. נמצאו {cve_count} פרצות רלוונטיות."
        else:
            summary = (
                f"נסרקו {len(packages)} חבילות מתוך {source}. "
                f"נמצאו פרצות ב-{len(findings)} חבילות."
            )
        return summary, report, validation

    def scan_dependencies(self, text, file_type, project_context="", log=no_log):
        packages = parsers.parse(text, file_type)
        return self.scan_packages(packages, file_type, project_context, log)

    def scan_github(self, url, project_context="", log=no_log):
        log("המתאם: התקבל קישור לריפו ב-GitHub - אוסף את קבצי התלויות", "agent")
        packages, repo_name = github.collect_packages(url, log)
        return self.scan_packages(packages, repo_name, project_context, log)

    def scan_file(self, path, project_context="", log=no_log):
        file_type = parsers.detect(path)
        if not file_type:
            raise ValueError("לא זוהה פורמט תלויות עבור הקובץ שהועלה")

        log(f"המתאם: התקבל הקובץ {Path(path).name} (זוהה כ-{file_type})", "agent")
        text = Path(path).read_text(encoding="utf-8")
        return self.scan_dependencies(text, file_type, project_context, log)

    def analyze_cve(self, cve_id, log=no_log):
        return self.analyst.analyze_single(cve_id, log)

    def chat(self, message, log=no_log):
        log("המתאם: התקבלה שאלה חופשית - מעביר ליועץ האבטחה", "agent")
        answer = self.advisor.chat(message, log)
        log("התשובה מוכנה", "done")
        return answer
