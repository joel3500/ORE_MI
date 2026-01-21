# entrainement_chat.py — IA refactorisée avec streaming (langue neutre)
import os
from typing import Generator


try:
    from openai import OpenAI
    _client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    _MODE = "v1"

except Exception:
    import openai as _openai
    _openai.api_key = os.getenv("OPENAI_API_KEY")
    _client = None
    _MODE = "legacy"

MODEL = os.getenv("OPENAI_MODEL", "gpt-5")
TEMP  = float(os.getenv("OPENAI_TEMP", "0.3"))

def _messages_for(prompt: str):
    return [
        {"role": "system", 
         "content": ( "You are a helpful mentor for students worldwide. "
                      "Respond in the user's language. If the language is unclear, ask a brief clarifying question. "
                      "Be clear, concise, and motivating."
                    ) 
        },
        {"role": "user", "content": prompt.strip()},
    ]

def generate_reply(prompt: str) -> str:
    if _MODE == "v1" and _client is not None:
        resp = _client.chat.completions.create(
            model=MODEL,
            messages=_messages_for(prompt),
            temperature=TEMP,
        )
        return resp.choices[0].message.content
    else:
        resp = _openai.ChatCompletion.create(
            model=MODEL,
            messages=_messages_for(prompt),
            temperature=TEMP,
            stream=False,
        )
        return resp["choices"][0]["message"]["content"]

def generate_reply_stream(prompt: str) -> Generator[str, None, None]:
    if _MODE == "v1" and _client is not None:
        stream = _client.chat.completions.create(
            model=MODEL,
            messages=_messages_for(prompt),
            temperature=TEMP,
            stream=True,
        )
        for event in stream:
            try:
                delta = event.choices[0].delta.content
            except Exception:
                delta = None
            if delta:
                yield delta
    else:
        stream = _openai.ChatCompletion.create(
            model=MODEL,
            messages=_messages_for(prompt),
            temperature=TEMP,
            stream=True,
        )
        for chunk in stream:
            try:
                delta = chunk["choices"][0]["delta"].get("content", "")
            except Exception:
                delta = ""
            if delta:
                yield delta
