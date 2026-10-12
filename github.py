"""איסוף קבצי התלויות מריפו ב-GitHub."""
import re
from urllib.parse import quote

import requests

import config
import parsers

API_URL = "https://api.github.com"
RAW_URL = "https://raw.githubusercontent.com"

# https://github.com/owner/repo, ואופציונלית /tree/branch/folder
REPO_URL = re.compile(
    r"^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/([^/]+)(?:/(.*))?)?/?$"
)

SKIP_FOLDERS = ("node_modules", "vendor", "dist", "build", ".git")


def _get(url):
    headers = {"Accept": "application/vnd.github+json"}
    if config.keys["github"]:
        headers["Authorization"] = f"Bearer {config.keys['github']}"

    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 404:
        raise ValueError("הריפו או הקובץ לא נמצאו. אם הריפו פרטי, הוסיפו GITHUB_TOKEN לקובץ .env.")
    if response.status_code == 403:
        raise ValueError("GitHub חסם את הבקשה, כנראה בגלל מגבלת קצב. הוסיפו GitHub Token או נסו שוב מאוחר יותר.")
    response.raise_for_status()
    return response


def parse_url(url):
    match = REPO_URL.match((url or "").strip())
    if not match:
        raise ValueError("זה לא נראה כמו קישור לריפו. דוגמה: https://github.com/owner/repo")
    owner, repo, branch, folder = match.groups()
    return owner, repo, branch, (folder or "").strip("/")


def _dependency_type(path):
    """מחזיר את סוג קובץ התלויות, או None אם זה קובץ אחר."""
    name = path.rsplit("/", 1)[-1].lower()
    if name in parsers.PARSERS:
        return name
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements.txt"
    if name.endswith(".gradle"):
        return "build.gradle"
    return None


def _folder_of(path):
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _find_dependency_files(tree, folder):
    files = []
    for item in tree:
        path = item["path"]
        if item["type"] != "blob":
            continue
        if folder and not path.startswith(folder + "/"):
            continue
        if any(part in SKIP_FOLDERS for part in path.split("/")[:-1]):
            continue

        file_type = _dependency_type(path)
        if file_type:
            files.append((path, file_type))

    # כשיש package-lock.json, הוא כבר מכיל את כל מה שב-package.json, עם גרסאות מדויקות
    lock_folders = {_folder_of(path) for path, kind in files if kind == "package-lock.json"}
    return [
        (path, kind) for path, kind in files
        if not (kind == "package.json" and _folder_of(path) in lock_folders)
    ]


def collect_packages(url, log):
    """מחזיר את כל החבילות מכל קבצי התלויות בריפו, ואת השם owner/repo."""
    owner, repo, branch, folder = parse_url(url)

    if not branch:
        branch = _get(f"{API_URL}/repos/{owner}/{repo}").json()["default_branch"]
    log(f"GitHub: קורא את מבנה הריפו {owner}/{repo} (ענף {branch})", "git")

    tree = _get(f"{API_URL}/repos/{owner}/{repo}/git/trees/{quote(branch, safe='')}?recursive=1").json()
    if tree.get("truncated"):
        log("הריפו גדול מאוד, ו-GitHub החזיר רק חלק מרשימת הקבצים", "warn")

    files = _find_dependency_files(tree.get("tree", []), folder)
    if not files:
        raise ValueError("לא נמצאו קבצי תלויות בריפו")
    log(f"נמצאו {len(files)} קבצי תלויות: {', '.join(path for path, _ in files)}")

    packages = []
    seen = set()
    for path, file_type in files:
        log(f"GitHub: מוריד את {path}", "git")
        text = _get(f"{RAW_URL}/{owner}/{repo}/{quote(branch)}/{quote(path)}").text

        try:
            found = parsers.parse(text, file_type)
        except Exception as error:
            log(f"לא הצלחתי לקרוא את {path}: {error}", "warn")
            continue

        for package in found:
            key = (package["ecosystem"], package["name"].lower(), package["version"])
            if key not in seen:
                seen.add(key)
                packages.append({**package, "file": path})

    return packages, f"{owner}/{repo}"
