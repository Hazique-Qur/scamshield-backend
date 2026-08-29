import os
from PIL import Image
from typing import Dict, List, Tuple
import numpy as np

try:
    import torch
    import torch.nn as nn
    from torchvision import models, transforms
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

if TORCH_AVAILABLE:
    DEVICE = torch.device("cpu")
    MODEL_DIR = "app/ml"
    os.makedirs(MODEL_DIR, exist_ok=True)
else:
    MODEL_DIR = "app/ml"
    os.makedirs(MODEL_DIR, exist_ok=True)


if TORCH_AVAILABLE:
    class ImageClassifier:
        def __init__(self):
            self.transform = transforms.Compose([
                transforms.Resize((224, 224)),
                transforms.ToTensor(),
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
            ])
            self.model = models.mobilenet_v2(weights=models.MobileNet_V2_Weights.DEFAULT)
            self.model.classifier[1] = nn.Linear(self.model.last_channel, 2)
            self.model.eval()
            self.model.to(DEVICE)
            self._load_model()

        def _load_model(self):
            path = os.path.join(MODEL_DIR, "mobilenet_image_model.pth")
            if os.path.exists(path):
                try:
                    state = torch.load(path, map_location=DEVICE)
                    self.model.load_state_dict(state)
                except Exception:
                    pass

        def predict(self, image_path: str) -> Dict[str, any]:
            try:
                img = Image.open(image_path).convert("RGB")
                tensor = self.transform(img).unsqueeze(0).to(DEVICE)
                with torch.no_grad():
                    outputs = self.model(tensor)
                    probs = torch.softmax(outputs, dim=1)
                    confidence, pred = torch.max(probs, 1)
                    label = "scam" if int(pred.item()) == 1 else "not_scam"
                    return {
                        "label": label,
                        "confidence": round(float(confidence.item()), 4),
                        "risk_score": round(float(probs[0][1].item()) * 100, 1),
                        "model": "MobileNetV2",
                        "framework": "PyTorch",
                    }
            except Exception:
                return {
                    "label": "unknown",
                    "confidence": 0.0,
                    "risk_score": 0.0,
                    "model": "MobileNetV2",
                    "framework": "PyTorch",
                }
else:
    class ImageClassifier:
        def predict(self, image_path: str) -> Dict[str, any]:
            return {
                "label": "unknown",
                "confidence": 0.0,
                "risk_score": 0.0,
                "model": "Unavailable",
                "framework": "None",
            }
# torch optional build

# Vercel torch fix

# vercel rebuild trigger
