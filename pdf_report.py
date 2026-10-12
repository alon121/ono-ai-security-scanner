"""
בונה עמוד HTML מעוצב של הדו"ח, שהדפדפן מדפיס ושומר כ-PDF.
הדפסה דרך הדפדפן מציגה עברית ו-RTL בצורה מדויקת, בלי ספריות PDF חיצוניות.
"""
import base64
import html
from datetime import datetime
from pathlib import Path

from markdown_it import MarkdownIt

# html=False: תגיות HTML שהמודל אולי כתב מוצגות כטקסט ולא מורצות
markdown = MarkdownIt("commonmark", {"html": False}).enable("table")

# הלוגו מוטמע בתוך ה-HTML, כדי שיופיע גם בממשק וגם ב-PDF בלי להגיש קבצים מהשרת
LOGO_FILE = Path(__file__).parent / "logo_web.png"
LOGO_DATA_URI = "data:image/png;base64," + base64.b64encode(LOGO_FILE.read_bytes()).decode()

PRINT_CSS = """
@page { size: A4; margin: 16mm 14mm; }
* { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font-family: "Heebo", Arial, sans-serif; color: #1f2937; line-height: 1.7; font-size: 11pt; margin: 0; }
header { display: flex; align-items: center; justify-content: space-between;
         border-bottom: 3px solid #4f46e5; padding-bottom: 10px; margin-bottom: 18px; }
.brand img { height: 52px; width: auto; display: block; }
.doc-title { font-size: 14pt; font-weight: 700; color: #4b5563; }
.meta { width: 100%; border-collapse: collapse; margin-bottom: 18px; background: #f6f7fb; }
.meta td { padding: 6px 12px; border: 1px solid #e6e8ef; }
.meta td:first-child { width: 110px; font-weight: 700; color: #4b5563; }
h1, h2, h3, h4 { color: #312e81; margin: 18px 0 6px; page-break-after: avoid; }
h2 { font-size: 14pt; border-bottom: 1px solid #e6e8ef; padding-bottom: 4px; }
h3 { font-size: 12pt; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 10pt; }
th, td { border: 1px solid #e6e8ef; padding: 5px 8px; text-align: right; }
th { background: #eef2ff; }
tr, li { page-break-inside: avoid; }
pre, code { direction: ltr; text-align: left; font-family: Consolas, monospace; font-size: 9.5pt; }
pre { background: #f3f4f6; padding: 8px 10px; border-radius: 6px; white-space: pre-wrap; }
code { background: #f3f4f6; padding: 0 4px; border-radius: 4px; }
.validation { margin-top: 22px; padding: 12px 16px; border: 1px solid #c7d2fe;
              border-radius: 8px; background: #f8f9ff; page-break-inside: avoid; }
.stamp { margin: -6px 0 18px; padding: 8px 14px; border-radius: 8px; font-weight: 700;
         background: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; }
.stamp.single { background: #f3f4f6; color: #4b5563; border-color: #e5e7eb; }
footer { margin-top: 28px; padding-top: 8px; border-top: 1px solid #e6e8ef;
         font-size: 9pt; color: #6b7280; text-align: center; }
"""


def build_report_html(file_name, summary, report, validation, verified):
    """מחזיר מסמך HTML מלא של הדו"ח, מוכן להדפסה."""
    now = datetime.now()
    title = f"OnoScan - {file_name} - {now:%Y-%m-%d}"

    if verified:
        stamp = '<div class="stamp">✔ אימות כפול: הדו"ח נכתב על ידי Claude ונבדק על ידי ChatGPT מול נתוני NVD</div>'
        validation_section = (
            '<section class="validation"><h3>הערות המודל המאמת (ChatGPT)</h3>'
            f"{markdown.render(validation)}</section>"
        )
    else:
        stamp = '<div class="stamp single">הדו"ח נכתב על ידי מודל אחד בלבד (Claude), ללא אימות מוצלב</div>'
        validation_section = ""

    return f"""<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<link href="https://fonts.googleapis.com/css2?family=Heebo:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>{PRINT_CSS}</style>
</head>
<body>
<header>
    <div class="brand"><img src="{LOGO_DATA_URI}" alt="OnoScan"></div>
    <div class="doc-title">דו"ח אבטחת חבילות קוד</div>
</header>
<table class="meta">
    <tr><td>קובץ</td><td>{html.escape(file_name)}</td></tr>
    <tr><td>תאריך</td><td>{now:%d/%m/%Y %H:%M}</td></tr>
    <tr><td>סיכום</td><td>{html.escape(summary)}</td></tr>
</table>
{stamp}
<main>{markdown.render(report)}</main>
{validation_section}
<footer>הופק על ידי OnoScan · פותח על ידי אלון אברג'ל, אסף שטיינברג ושי צפריר</footer>
</body>
</html>"""
