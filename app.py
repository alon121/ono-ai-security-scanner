"""ממשק הווב של המערכת (Gradio). כל פעולה מועברת למתאם שב-agents.py."""
import html
import threading
import time
from pathlib import Path

import gradio as gr

import agents
import config
import pdf_report

HERE = Path(__file__).parent
SAMPLE_FILE = HERE / "samples" / "requirements.txt"

coordinator = agents.Coordinator()

AGENT_PIPELINE = ["המתאם", "סורק החבילות", "אנליסט ה-CVE", "יועץ האבטחה"]

EXAMPLE_QUESTIONS = [
    "מה המשמעות של CVE-2024-3094 וכמה דחוף לטפל בו?",
    "יש לי חבילה שלא מתוחזקת כבר 4 שנים, מה החלופות?",
    "למה פרצה בחבילת dev לא תמיד דורשת טיפול?",
]

LOGO = f'<div class="logo"><img src="{pdf_report.LOGO_DATA_URI}" alt="OnoScan"></div>'

HERO = """
<div class="hero">
    <h1>סריקת אבטחה לחבילות קוד, בעברית ובשפה פשוטה</h1>
    <p>
        OnoScan בודקת קובץ תלויות, ריפו שלם מ-GitHub, או חבילה ומוצר בודדים מול מאגר הפרצות הרשמי NVD,
        ובעזרת שני מודלי AI מפיקה דו"ח מתועדף: מה לתקן עכשיו, מה יכול לחכות, וממה אפשר להתעלם.
    </p>
    <div class="dual">
        <span class="dual-tag">🛡️ אימות כפול</span>
        <div class="model">
            <span class="model-name">Claude Opus 5.5</span>
            <span class="model-role">בודק כל חבילה, מתעדף וכותב את הדו"ח</span>
        </div>
        <span class="arrow">←</span>
        <div class="model">
            <span class="model-name">ChatGPT 5.6</span>
            <span class="model-role">בודק אותו מול נתוני NVD</span>
        </div>
    </div>
</div>
"""

MODEL_STEPS = [
    ("claude", "Claude", "בודק את החבילות וכותב את הדו\"ח"),
    ("gpt", "ChatGPT", "מאמת את הדו\"ח"),
]

STEP_LABELS = {
    "waiting": "ממתין",
    "working": "עובד...",
    "done": "הושלם",
    "skipped": "לא הופעל",
    "error": "נכשל",
}

CREDITS = """
<div class="credits">פותח על ידי אלון אברג'ל · אסף שטיינברג · שי צפריר</div>
"""

CHAT_WELCOME = """
<div class="chat-welcome">
    <b>שלום, אני יועץ האבטחה של OnoScan</b>
    <span>שאלו אותי על CVE מסוים, על חבילה, או על חלופות בטוחות יותר.</span>
</div>
"""

EMPTY_REPORT = '<div class="empty">הדו"ח יופיע כאן אחרי הסריקה.</div>'

PAGE_SETUP = """() => {
    document.documentElement.setAttribute('dir', 'rtl');
    document.documentElement.setAttribute('lang', 'he');
    document.body.classList.remove('dark');
}"""
PICK_FILE = "() => { document.querySelector('#upload input[type=file]')?.click(); }"

# מדפיס את הדו"ח מתוך iframe נסתר. בחלון ההדפסה בוחרים "שמירה כ-PDF".
PRINT_REPORT = """(reportHtml) => {
    if (!reportHtml) return;
    const frame = document.createElement('iframe');
    frame.style.cssText = 'position:fixed; width:0; height:0; border:0;';
    document.body.appendChild(frame);
    frame.contentDocument.open();
    frame.contentDocument.write(reportHtml);
    frame.contentDocument.close();

    setTimeout(async () => {
        await frame.contentDocument.fonts.ready;
        const pageTitle = document.title;
        document.title = frame.contentDocument.title;
        frame.contentWindow.focus();
        frame.contentWindow.print();
        document.title = pageTitle;
        setTimeout(() => frame.remove(), 1000);
    }, 600);
}"""


def build_theme():
    """ערכת עיצוב בהירה. אותם צבעים גם במצב כהה, כדי שהמראה יהיה קבוע."""
    palette = {
        "body_background_fill": "#f6f7fb",
        "body_text_color": "#1f2937",
        "body_text_color_subdued": "#6b7280",
        "background_fill_primary": "#ffffff",
        "background_fill_secondary": "#f9fafb",
        "block_background_fill": "#ffffff",
        "block_border_color": "#e6e8ef",
        "block_label_text_color": "#4b5563",
        "block_title_text_color": "#1f2937",
        "border_color_primary": "#e6e8ef",
        "input_background_fill": "#ffffff",
        "input_border_color": "#e2e5ec",
        "input_placeholder_color": "#9ca3af",
        "button_primary_background_fill": "#4f46e5",
        "button_primary_background_fill_hover": "#4338ca",
        "button_primary_text_color": "#ffffff",
        "button_secondary_background_fill": "#ffffff",
        "button_secondary_background_fill_hover": "#f3f4f6",
        "button_secondary_text_color": "#1f2937",
        "color_accent_soft": "#eef2ff",
    }
    settings = {}
    for name, value in palette.items():
        settings[name] = value
        settings[name + "_dark"] = value

    theme = gr.themes.Base(
        primary_hue="indigo",
        neutral_hue="gray",
        font=[gr.themes.GoogleFont("Heebo"), "Arial", "sans-serif"],
        font_mono=[gr.themes.GoogleFont("JetBrains Mono"), "Consolas", "monospace"],
        radius_size="lg",
    )
    return theme.set(**settings)


def render_status():
    services = [
        ("Claude", bool(config.keys["anthropic"])),
        ("ChatGPT", bool(config.keys["openai"])),
        ("NVD", True),
    ]
    pills = "".join(
        f'<span class="status-pill"><span class="dot {"on" if ok else "off"}"></span>{name}</span>'
        for name, ok in services
    )
    return f'<div class="status">{pills}</div>'


def render_summary(text, state):
    icons = {"running": "⏳", "done": "✅", "error": "⚠️"}
    return f'<div class="summary {state}">{icons[state]} {html.escape(text)}</div>'


def model_states(lines):
    """מסיק משורות הלוג באיזה שלב נמצא כל אחד משני המודלים."""
    states = {"claude": "waiting", "gpt": "waiting"}
    for _, _, text in lines:
        for key, name in (("claude", "Claude"), ("gpt", "ChatGPT")):
            if f"מפעיל את {name}" in text:
                states[key] = "working"
            elif text.startswith(f"{name} סיים"):
                states[key] = "done"
            elif text.startswith(f"{name} נכשל"):
                states[key] = "error"
        if "מדלג על האימות" in text:
            states["gpt"] = "skipped"
    return states


def render_verification(states, validation=""):
    """הפאנל שמראה ששני מודלים עבדו על הדו"ח, ומה הייתה מסקנת האימות."""
    steps = []
    for key, name, role in MODEL_STEPS:
        state = states[key]
        steps.append(
            f'<div class="step {state}"><span class="step-icon"></span>'
            f'<div><b>{name}</b><small>{role}</small></div>'
            f'<span class="step-state">{STEP_LABELS[state]}</span></div>'
        )

    verdict = ""
    if states["gpt"] == "done":
        if "ללא הערות מהותיות" in validation:
            verdict = '<div class="verdict ok">✔ שני המודלים מסכימים: הדו"ח אומת ללא הערות מהותיות</div>'
        else:
            verdict = '<div class="verdict notes">⚑ המודל המאמת מצא הערות. ראו פירוט מתחת לדו"ח</div>'
    elif states["gpt"] == "skipped":
        verdict = '<div class="verdict off">הדו"ח נכתב על ידי מודל אחד בלבד. הוסיפו מפתח OpenAI כדי להפעיל אימות כפול</div>'

    return (
        '<div class="verify"><div class="verify-title">אימות כפול · שני מודלים</div>'
        f'<div class="steps">{steps[0]}<span class="step-arrow">←</span>{steps[1]}</div>'
        f"{verdict}</div>"
    )


def render_console(lines, running=False):
    """בונה את חלון הקונסולה. כל שורה היא (זמן, סוג, טקסט)."""
    active = None
    if running:
        for _, _, text in reversed(lines):
            active = next((name for name in AGENT_PIPELINE if text.startswith(name)), None)
            if active:
                break

    agents_row = "".join(
        f'<span class="agent-chip {"active" if name == active else ""}">{name}</span>'
        for name in AGENT_PIPELINE
    )

    rows = [
        f'<div class="line {kind}"><span class="time">{stamp}</span>{html.escape(text)}</div>'
        for stamp, kind, text in lines
    ]
    if running:
        rows.append('<div class="line"><span class="cursor">▍</span></div>')
    if not rows:
        rows.append('<div class="line idle">כאן תראו בזמן אמת מה כל סוכן עושה ואיזה מודל מופעל.</div>')

    badge = '<span class="live">פועל</span>' if running else ""

    return f"""
<div id="console">
    <div class="console-head">
        <div class="console-title">קונסולת הסוכנים {badge}</div>
        <div class="agents">{agents_row}</div>
    </div>
    <div class="console-body"><div>{"".join(rows)}</div></div>
</div>"""


def run_live(task):
    """
    מריץ את task ברקע ומחזיר שוב ושוב (סיים?, תוצאה, שורות הלוג).
    task מקבל פונקציית log. אם task נכשל, התוצאה היא החריגה.
    """
    lines = []
    started = time.time()
    result = {}

    def log(text, kind="info"):
        elapsed = int(time.time() - started)
        lines.append((f"{elapsed // 60:02d}:{elapsed % 60:02d}", kind, text))

    def worker():
        try:
            result["value"] = task(log)
        except Exception as error:
            log(f"שגיאה: {error}", "error")
            result["value"] = error

    thread = threading.Thread(target=worker)
    thread.start()
    while thread.is_alive():
        yield False, None, lines
        thread.join(timeout=0.4)

    yield True, result["value"], lines


def scan_selected(source, file_path, repo_url, product_name, product_version, context):
    """כפתור הסריקה: סורק את מה שנבחר בלשונית - קובץ, ריפו, או חבילה בודדת."""
    if source == "repo":
        yield from scan_repo(repo_url, context)
    elif source == "product":
        yield from scan_product(product_name, product_version, context)
    else:
        yield from scan(file_path, context)


def scan_product(name, version, context):
    name, version = (name or "").strip(), (version or "").strip()
    if not name:
        yield render_summary("כתבו שם של חבילה או מוצר לבדיקה.", "error"), *[gr.skip()] * 7
        return

    task = lambda log: coordinator.scan_product(name, version, context, log)
    yield from stream_scan(f"{name} {version}".strip(), task)


def scan_repo(repo_url, context):
    if not (repo_url or "").strip():
        yield render_summary("הדביקו קישור לריפו ב-GitHub לפני הסריקה.", "error"), *[gr.skip()] * 7
        return

    repo_name = repo_url.strip().rstrip("/").split("github.com/")[-1]
    task = lambda log: coordinator.scan_github(repo_url, context, log)
    yield from stream_scan(repo_name, task)


def scan(file_path, context):
    if not file_path:
        yield render_summary("בחרו קובץ תלויות לפני הסריקה.", "error"), *[gr.skip()] * 7
        return

    task = lambda log: coordinator.scan_file(file_path, context, log)
    yield from stream_scan(Path(file_path).name, task)


def stream_scan(name, task):
    """
    מריץ סריקה ומחזיר עדכונים ל: סיכום, פאנל האימות הכפול, דו"ח, הערות האימות,
    תיבת ההערות, קונסולה, HTML להדפסה, כפתור ה-PDF.
    """
    hidden = gr.update(visible=False)

    for done, result, lines in run_live(task):
        states = model_states(lines)

        if not done:
            yield (
                render_summary(f"סורק את {name}...", "running"),
                render_verification(states),
                '<div class="empty">הסוכנים עובדים. אפשר לעקוב בקונסולת הסוכנים.</div>',
                "",
                hidden,
                render_console(lines, running=True),
                "",
                hidden,
            )
        elif isinstance(result, Exception):
            yield (
                render_summary(str(result), "error"),
                render_verification(states),
                EMPTY_REPORT,
                "",
                hidden,
                render_console(lines),
                "",
                hidden,
            )
        else:
            summary, report, validation = result
            verified = states["gpt"] == "done"
            printable = pdf_report.build_report_html(name, summary, report, validation, verified)
            yield (
                render_summary(summary, "done"),
                render_verification(states, validation),
                report,
                validation,
                gr.update(visible=verified),
                render_console(lines),
                printable,
                gr.update(visible=bool(report)),
            )


def scan_sample(context):
    """סורק את קובץ הדוגמה, ומעביר את הממשק ללשונית הקובץ."""
    for update in scan(str(SAMPLE_FILE), context):
        yield gr.Tabs(selected="file"), "file", str(SAMPLE_FILE), *update


def show_console():
    return gr.Tabs(selected="console")


def show_chat():
    return gr.Tabs(selected="chat")


def show_repo_tab():
    return gr.Tabs(selected="repo"), "repo"


def ask(question, history):
    """מחזיר עדכונים ל: תיבת השאלה, הצ'אט, קונסולה."""
    question = (question or "").strip()
    if not question:
        yield gr.skip(), history, gr.skip()
        return

    history = history + [{"role": "user", "content": question}]

    for done, answer, lines in run_live(lambda log: coordinator.chat(question, log)):
        if not done:
            thinking = {"role": "assistant", "content": "", "metadata": {"title": "חושב...", "status": "pending"}}
            yield "", history + [thinking], render_console(lines, running=True)
        else:
            if isinstance(answer, Exception):
                answer = f"⚠️ {answer}"
            yield "", history + [{"role": "assistant", "content": answer}], render_console(lines)


def ask_example(history, evt: gr.SelectData):
    yield from ask(evt.value.get("text", ""), history)


with gr.Blocks(title="OnoScan - סריקת אבטחה לחבילות קוד", fill_width=True) as app:
    with gr.Row(elem_id="header"):
        gr.HTML(LOGO, padding=False)
        status = gr.HTML(render_status(), padding=False)

    gr.HTML(HERO, padding=False)
    with gr.Row(elem_id="actions"):
        pick_btn = gr.Button("📂 העלאת קובץ לסריקה", variant="primary")
        repo_btn = gr.Button("🐙 סריקת ריפו מ-GitHub")
        sample_btn = gr.Button("🧪 נסו עם קובץ דוגמה")
        open_chat_btn = gr.Button("💬 שאלו את יועץ ה-AI")

    with gr.Row(elem_id="workspace", equal_height=False):
        with gr.Column(scale=4, min_width=320, elem_classes="card"):
            gr.HTML('<div class="card-title">מה לסרוק?</div>', padding=False)
            source = gr.State("file")
            with gr.Tabs(selected="file", elem_id="source-tabs") as source_tabs:
                with gr.Tab("📂 קובץ", id="file") as file_tab:
                    upload = gr.File(
                        label="requirements.txt, package.json, pom.xml ועוד",
                        type="filepath",
                        elem_id="upload",
                    )
                with gr.Tab("🐙 ריפו ב-GitHub", id="repo") as repo_tab:
                    repo_url = gr.Textbox(
                        label="קישור לריפו",
                        placeholder="https://github.com/owner/repo",
                        elem_id="repo-url",
                    )
                    gr.HTML(
                        '<div class="hint">המערכת תמצא את כל קבצי התלויות בריפו ותסרוק את כולם יחד. '
                        "לריפו פרטי צריך GITHUB_TOKEN בקובץ ‎.env.</div>",
                        padding=False,
                    )
                with gr.Tab("📦 חבילה / מוצר", id="product") as product_tab:
                    with gr.Row():
                        product_name = gr.Textbox(
                            label="שם החבילה או המוצר",
                            placeholder="wordpress, log4j, django...",
                            scale=3,
                        )
                        product_version = gr.Textbox(label="גרסה (לא חובה)", placeholder="6.2", scale=2)
                    gr.HTML(
                        '<div class="hint">עם גרסה, המערכת מציגה רק פרצות שבאמת משפיעות עליה. '
                        "בלי גרסה, יוצגו הפרצות החמורות ביותר במוצר.</div>",
                        padding=False,
                    )
            context = gr.Textbox(
                label="על הפרויקט (לא חובה)",
                placeholder="לדוגמה: API פנימי ב-Django, רץ בקונטיינר מאחורי VPN",
                lines=3,
                rtl=True,
            )
            scan_btn = gr.Button("סרוק עכשיו", variant="primary", size="lg")

        with gr.Column(scale=6, min_width=380, elem_id="console-col"):
            with gr.Tabs(selected="console", elem_id="side-tabs") as side_tabs:
                with gr.Tab("🖥️ קונסולת הסוכנים", id="console"):
                    console = gr.HTML(render_console([]), padding=False)
                with gr.Tab("💬 יועץ ה-AI", id="chat"):
                    chatbot = gr.Chatbot(
                        show_label=False,
                        rtl=True,
                        height=430,
                        placeholder=CHAT_WELCOME,
                        examples=[{"text": question} for question in EXAMPLE_QUESTIONS],
                        buttons=["copy"],
                        elem_id="chat",
                    )
                    question = gr.Textbox(
                        show_label=False,
                        placeholder="כתבו שאלה...",
                        rtl=True,
                        submit_btn=True,
                        elem_id="chat-input",
                    )

    with gr.Column(elem_classes="card", elem_id="report-card"):
        with gr.Row(elem_id="report-head"):
            gr.HTML('<div class="card-title">דו"ח אבטחה</div>', padding=False)
            export_btn = gr.Button("📄 ייצוא ל-PDF", size="sm", visible=False, elem_id="export-btn")
        summary = gr.HTML("", padding=False)
        verification = gr.HTML(render_verification(model_states([])), padding=False)
        report_html = gr.Textbox(elem_id="report-html", show_label=False, container=False)
        report = gr.Markdown(EMPTY_REPORT, rtl=True, elem_id="report")
        with gr.Column(visible=False, elem_id="validation-box") as validation_box:
            gr.HTML('<div class="validation-title">🔎 הערות המודל המאמת (ChatGPT)</div>', padding=False)
            validation = gr.Markdown(rtl=True)

    gr.HTML(CREDITS, padding=False)

    scan_outputs = [
        summary, verification, report, validation, validation_box, console, report_html, export_btn,
    ]
    file_tab.select(lambda: "file", None, source)
    repo_tab.select(lambda: "repo", None, source)
    product_tab.select(lambda: "product", None, source)

    # כל סריקה מחזירה את הפאנל השמאלי לקונסולה, כדי לראות את הסוכנים בעבודה
    for trigger in (scan_btn.click, repo_url.submit, product_name.submit,
                    product_version.submit, sample_btn.click):
        trigger(show_console, None, side_tabs)

    scan_btn.click(
        scan_selected,
        [source, upload, repo_url, product_name, product_version, context],
        scan_outputs,
    )
    repo_url.submit(scan_repo, [repo_url, context], scan_outputs)
    product_name.submit(scan_product, [product_name, product_version, context], scan_outputs)
    product_version.submit(scan_product, [product_name, product_version, context], scan_outputs)
    sample_btn.click(scan_sample, [context], [source_tabs, source, upload, *scan_outputs])
    pick_btn.click(lambda: (gr.Tabs(selected="file"), "file"), None, [source_tabs, source]).then(
        None, js=PICK_FILE
    )
    repo_btn.click(show_repo_tab, None, [source_tabs, source]).then(
        None, js="() => { document.querySelector('#repo-url textarea, #repo-url input')?.focus(); }"
    )
    export_btn.click(None, [report_html], js=PRINT_REPORT)

    chat_outputs = [question, chatbot, console]
    question.submit(ask, [question, chatbot], chat_outputs)
    chatbot.example_select(ask_example, [chatbot], chat_outputs)

    open_chat_btn.click(show_chat, None, side_tabs).then(
        None, js="() => { setTimeout(() => document.querySelector('#chat-input textarea')?.focus(), 150); }"
    )


if __name__ == "__main__":
    app.launch(
        server_name="127.0.0.1",
        server_port=7860,
        inbrowser=True,
        theme=build_theme(),
        css_paths=[HERE / "style.css"],
        js=PAGE_SETUP,
        footer_links=[],
        allowed_paths=[str(SAMPLE_FILE.parent)],
    )
