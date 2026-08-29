import re
from typing import List, Dict, Any
from app.models.scan import Scan


class TextAnalyzer:
    PATTERNS = {
        "urgency": [
            (r"\b(urgent|immediately|right away|asap|within \d+ minutes?|act now|hurry|limited time|expire)\b", 1.0),
            (r"\b(now|today|before it'?s too late|don'?t wait|final notice)\b", 0.6),
        ],
        "financial_request": [
            (r"\b(payment|fee|transfer|send money|wire|deposit|payment method|cashapp|venmo|bitcoin|crypto|bank account)\b", 1.0),
            (r"\b(money|cash|pay|invoice|charge|billing|account number|routing)\b", 0.7),
        ],
        "credential_request": [
            (r"\b(password|otp|one.time code|verification code|pin|ssn|social security|cvv|security code)\b", 1.0),
            (r"\b(login|sign in|verify your|confirm your|update your account|credential)\b", 0.8),
        ],
        "impersonation": [
            (r"\b(bank|government|support|account department|irs|police|court|legal|immigration|tax)\b", 0.7),
            (r"\b(dear customer|dear user|dear member|valued customer)\b", 0.6),
        ],
        "suspicious_promise": [
            (r"\b(winner|prize|won|selected|congratulations|guaranteed|free money|lottery|inheritance|claim)\b", 1.0),
            (r"\b(you have been chosen|exclusive offer|limited offer|no risk)\b", 0.8),
        ],
        "suspicious_url": [
            (r"\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|adf\.ly|buff\.ly)\b", 0.8),
            (r"https?://(?!.*(?:amazon|google|microsoft|apple|paypal|github|facebook|instagram|twitter|linkedin))[^\s/$.?#].[^\s]*", 0.4),
        ],
    }

    def analyze(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        signals: List[Dict[str, Any]] = []
        total_weighted = 0.0
        total_possible = 0.0

        for category, patterns in self.PATTERNS.items():
            category_score = 0.0
            matched = []
            for pattern, weight in patterns:
                found = re.findall(pattern, text_lower, flags=re.IGNORECASE)
                if found:
                    category_score = max(category_score, weight)
                    matched.extend(found)
            if category_score > 0:
                signals.append({
                    "category": category,
                    "score": category_score,
                    "matched_terms": list(set(matched)),
                })
                total_weighted += category_score
                total_possible += 1.0

        raw_score = (total_weighted / total_possible * 100) if total_possible > 0 else 0.0
        risk_score = min(100.0, max(0.0, raw_score))
        return {
            "risk_score": risk_score,
            "signals": signals,
            "text_length": len(text),
        }
