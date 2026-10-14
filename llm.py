"""גישה לשני מודלי ה-AI: Claude ו-ChatGPT. בשגיאה מוחזרת הודעה כטקסט."""
from anthropic import Anthropic
from openai import OpenAI

import config

OPENROUTER_URL = "https://openrouter.ai/api/v1"


def _openrouter_chat(model, system, prompt, max_tokens=None):
    client = OpenAI(api_key=config.keys["openrouter"], base_url=OPENROUTER_URL)
    kwargs = {"max_tokens": max_tokens} if max_tokens else {}
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        **kwargs,
    )
    return response.choices[0].message.content or ""


def ask_claude(system, prompt):
    if config.keys["openrouter"]:
        try:
            return _openrouter_chat(config.models["claude"], system, prompt, 6000)
        except Exception as error:
            return f"שגיאת OpenRouter: {error}"

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
    if config.keys["openrouter"]:
        try:
            return _openrouter_chat(config.models["gpt"], system, prompt)
        except Exception as error:
            return f"שגיאת OpenRouter: {error}"

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


def has_claude():
    return bool(config.keys["openrouter"] or config.keys["anthropic"])


def has_gpt():
    return bool(config.keys["openrouter"] or config.keys["openai"])
