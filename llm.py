"""גישה לשני מודלי ה-AI: Claude ו-ChatGPT. בשגיאה מוחזרת הודעה כטקסט."""
from anthropic import Anthropic
from openai import OpenAI

import config


def ask_claude(system, prompt):
    if not config.keys["anthropic"]:
        return "שגיאה: לא הוגדר ANTHROPIC_API_KEY"

    try:
        client = Anthropic(api_key=config.keys["anthropic"])
        response = client.messages.create(
            model=config.models["claude"],
            max_tokens=6000,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        text_parts = [block.text for block in response.content if block.type == "text"]
        return "".join(text_parts)

    except Exception as error:
        return f"שגיאת Claude: {error}"


def ask_gpt(system, prompt):
    if not config.keys["openai"]:
        return "שגיאה: לא הוגדר OPENAI_API_KEY"

    try:
        client = OpenAI(api_key=config.keys["openai"])
        response = client.chat.completions.create(
            model=config.models["gpt"],
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content

    except Exception as error:
        return f"שגיאת ChatGPT: {error}"


def has_gpt():
    return bool(config.keys["openai"])
