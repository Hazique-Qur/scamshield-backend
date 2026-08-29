import re


def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"https?://\S+|www\.\S+", "<url>", text)
    text = re.sub(r"\b\d{10,}\b", "<number>", text)
    return text.strip()


def extract_features(text: str) -> dict:
    return {
        "length": len(text),
        "uppercase_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),
        "exclamation_count": text.count("!"),
        "question_count": text.count("?"),
        "has_url": 1 if re.search(r"https?://\S+|www\.\S+", text) else 0,
        "has_urgency": 1 if re.search(r"\b(urgent|immediately|asap|act now)\b", text, re.IGNORECASE) else 0,
        "has_money": 1 if re.search(r"\b(payment|fee|transfer|send money|bank account)\b", text, re.IGNORECASE) else 0,
    }
