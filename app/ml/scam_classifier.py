import os
import json
import joblib
import numpy as np
from typing import List, Dict, Tuple, Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

MODEL_DIR = "app/ml"
os.makedirs(MODEL_DIR, exist_ok=True)


class ScamClassifier:
    def __init__(self, model_type: str = "random_forest"):
        self.model_type = model_type
        self.vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words="english")
        self.model = None
        self._load_model()

    def _get_model(self):
        if self.model_type == "logistic":
            return LogisticRegression(max_iter=1000, random_state=42)
        if self.model_type == "svm":
            return LinearSVC(random_state=42)
        return RandomForestClassifier(n_estimators=200, random_state=42)

    def train(self, texts: List[str], labels: List[int]) -> Dict[str, float]:
        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)
        self.model = self._get_model()
        self.model.fit(X, y)
        return self._evaluate(X, y)

    def evaluate(self, texts: List[str], labels: List[int]) -> Dict[str, float]:
        X = self.vectorizer.transform(texts)
        y = np.array(labels)
        return self._evaluate(X, y)

    def _evaluate(self, X, y) -> Dict[str, float]:
        preds = self.model.predict(X)
        return {
            "accuracy": round(float(accuracy_score(y, preds)), 4),
            "precision": round(float(precision_score(y, preds, zero_division=0)), 4),
            "recall": round(float(recall_score(y, preds, zero_division=0)), 4),
            "f1": round(float(f1_score(y, preds, zero_division=0)), 4),
        }

    def predict_proba(self, text: str) -> float:
        if not self.model:
            return 0.0
        x = self.vectorizer.transform([text])
        if hasattr(self.model, "predict_proba"):
            return float(self.model.predict_proba(x)[0][1])
        decision = self.model.decision_function(x)
        return float(1.0 / (1.0 + np.exp(-decision)))

    def predict(self, text: str) -> Dict[str, any]:
        prob = self.predict_proba(text)
        label = "scam" if prob >= 0.5 else "not_scam"
        return {
            "label": label,
            "probability": round(prob, 4),
            "risk_score": round(prob * 100, 1),
        }

    def save(self) -> None:
        if not self.model:
            raise RuntimeError("Model not trained")
        joblib.dump(self.vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))
        joblib.dump(self.model, os.path.join(MODEL_DIR, f"{self.model_type}_model.pkl"))
        with open(os.path.join(MODEL_DIR, "model_meta.json"), "w", encoding="utf-8") as f:
            json.dump({"model_type": self.model_type}, f)

    def _load_model(self) -> None:
        meta_path = os.path.join(MODEL_DIR, "model_meta.json")
        if not os.path.exists(meta_path):
            return
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.model_type = meta.get("model_type", self.model_type)
        vec_path = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
        model_path = os.path.join(MODEL_DIR, f"{self.model_type}_model.pkl")
        if os.path.exists(vec_path) and os.path.exists(model_path):
            self.vectorizer = joblib.load(vec_path)
            self.model = joblib.load(model_path)
