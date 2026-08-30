import os
from PIL import Image
from typing import Dict
import numpy as np

MODEL_DIR = "app/ml"
os.makedirs(MODEL_DIR, exist_ok=True)


class ImageClassifier:
    def predict(self, image_path: str) -> Dict[str, any]:
        return {
            "label": "unknown",
            "confidence": 0.0,
            "risk_score": 0.0,
            "model": "Unavailable",
            "framework": "None",
        }
