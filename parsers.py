"""
קריאה של קבצי תלויות.
כל פונקציה מחזירה רשימה של (שם, גרסה, מאגר), למשל ("django", "3.1.0", "PyPI").
"""
import json
import re
from pathlib import Path


def _clean_version(version):
    """למשל: "^4.17.1" -> "4.17.1"."""
    cleaned = re.sub(r"^[\^~>=<!\s*v]+", "", version or "").strip()
    return cleaned or "לא צוין"


def parse_requirements(text):
    packages = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue

        match = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*([=<>~!].*)?$", line)
        if match:
            name, version = match.group(1), match.group(2)
            packages.append((name, _clean_version(version), "PyPI"))
    return packages


def parse_pipfile(text):
    packages = []
    inside_packages = False

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            inside_packages = "packages" in line
        elif inside_packages and "=" in line:
            name, version = line.split("=", 1)
            name = name.strip().strip('"')
            version = version.strip(' "{}')
            packages.append((name, _clean_version(version), "PyPI"))
    return packages


def parse_package_json(text):
    data = json.loads(text)
    packages = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            packages.append((name, _clean_version(version), "npm"))
    return packages


def parse_package_lock(text):
    """כולל גם תלויות עקיפות. חבילה שמופיעה כמה פעמים באותה גרסה נספרת פעם אחת."""
    data = json.loads(text)
    found = set()

    # גרסה 2 ו-3 של הקובץ: {"node_modules/name": {"version": ...}}
    for path, info in (data.get("packages") or {}).items():
        if path and info.get("version"):
            name = path.split("node_modules/")[-1]
            found.add((name, info["version"]))

    # גרסה 1 של הקובץ: תלויות מקוננות תחת "dependencies"
    def collect(dependencies):
        for name, info in (dependencies or {}).items():
            if info.get("version"):
                found.add((name, info["version"]))
            collect(info.get("dependencies"))

    if not found:
        collect(data.get("dependencies"))

    return [(name, _clean_version(version), "npm") for name, version in sorted(found)]


def parse_composer(text):
    data = json.loads(text)
    packages = []
    for section in ("require", "require-dev"):
        for name, version in (data.get(section) or {}).items():
            if name == "php":
                continue
            packages.append((name, _clean_version(version), "Packagist"))
    return packages


def parse_go_mod(text):
    packages = []
    for line in text.splitlines():
        line = line.strip().replace("require ", "")
        match = re.match(r"^([\w.\-/]+\.[\w.\-/]+)\s+v([\w.\-+]+)", line)
        if match:
            packages.append((match.group(1), match.group(2), "Go"))
    return packages


def parse_pom_xml(text):
    pattern = (
        r"<groupId>(.*?)</groupId>\s*"
        r"<artifactId>(.*?)</artifactId>\s*"
        r"<version>(.*?)</version>"
    )
    packages = []
    for group, artifact, version in re.findall(pattern, text, re.DOTALL):
        name = f"{group.strip()}:{artifact.strip()}"
        packages.append((name, version.strip(), "Maven"))
    return packages


def parse_gradle(text):
    pattern = r"['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]"
    packages = []
    for group, artifact, version in re.findall(pattern, text):
        packages.append((f"{group}:{artifact}", version, "Maven"))
    return packages


def parse_cargo(text):
    packages = []
    inside_dependencies = False

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            inside_dependencies = "dependencies" in line
        elif inside_dependencies and "=" in line:
            name, version = line.split("=", 1)
            version = version.strip(' "{}')
            packages.append((name.strip(), _clean_version(version), "crates.io"))
    return packages


def parse_gemfile(text):
    pattern = r"gem\s+['\"]([\w.\-]+)['\"](?:\s*,\s*['\"][^\d]*([\d.]+)['\"])?"
    packages = []
    for match in re.finditer(pattern, text):
        name = match.group(1)
        version = match.group(2) or "לא צוין"
        packages.append((name, version, "RubyGems"))
    return packages


PARSERS = {
    "requirements.txt": parse_requirements,
    "pipfile": parse_pipfile,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "composer.json": parse_composer,
    "go.mod": parse_go_mod,
    "pom.xml": parse_pom_xml,
    "build.gradle": parse_gradle,
    "cargo.toml": parse_cargo,
    "gemfile": parse_gemfile,
}


def detect(file_name):
    """מזהה את סוג הקובץ לפי השם. מחזיר None אם לא זוהה."""
    name = Path(file_name).name.lower()

    if name in PARSERS:
        return name
    if name.endswith(".txt"):
        return "requirements.txt"
    if name.endswith(".gradle"):
        return "build.gradle"
    return None


def parse(text, file_type):
    parser = PARSERS.get(file_type)
    if not parser:
        raise ValueError(f"פורמט לא נתמך: {file_type}")

    return [
        {"name": name, "version": version, "ecosystem": ecosystem}
        for name, version, ecosystem in parser(text)
    ]
