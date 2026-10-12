"""הגדרות ומפתחות API של המערכת."""
import os

from dotenv import load_dotenv

# שימוש בתעודות של מערכת ההפעלה, נדרש ברשתות עם proxy ארגוני
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

load_dotenv()

keys = {
    "anthropic": os.getenv("ANTHROPIC_API_KEY", ""),
    "openai": os.getenv("OPENAI_API_KEY", ""),
    "nvd": os.getenv("NVD_API_KEY", ""),
    "github": os.getenv("GITHUB_TOKEN", ""),
}

models = {
    "claude": os.getenv("CLAUDE_MODEL", "claude-opus-5-5"),
    "gpt": os.getenv("OPENAI_MODEL", "gpt-5.6"),
}
