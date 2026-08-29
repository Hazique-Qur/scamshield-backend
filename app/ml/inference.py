from typing import Any
from app.ml.preprocessing.text import clean_text, extract_features


class DummyScamClassifier:
    def predict_proba(self, text: str) -> float:
        cleaned = clean_text(text)
        features = extract_features(cleaned)
        score = 0.0
        score += features.get("has_urgency", 0) * 20
        score += features.get("has_money", 0) * 25
        score += features.get("has_url", 0) * 10
        score += features.get("exclamation_count", 0) * 5
        return min(100.0, max(0.0, score))


class InferenceEngine:
    def __init__(self):
        self.model = DummyScamClassifier()

    def score(self, text: str) -> float:
        return float(self.model.predict_proba(text))
