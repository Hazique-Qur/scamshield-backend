import re
import os
import uuid
import pytesseract
from PIL import Image, ImageDraw
from typing import List, Dict, Any, Tuple
from app.models.scan import Scan
from app.services.ai_service import AIService
from app.models.indicator import Indicator
from app.models.evidence import Evidence


class ImageAnalyzer:
    def __init__(self):
        self.ai_service = AIService()

    async def analyze(self, image_path: str, scan_id: str) -> dict:
        extracted = self._extract_structured(image_path)
        ocr_text = extracted.get("text", "") or ""
        vision_text = await self._analyze_vision(image_path)
        combined_text = f"{vision_text}\n{ocr_text}".strip()

        signals = self._detect_signals(ocr_text, vision_text, extracted)
        summary = self._build_summary(signals, vision_text, ocr_text)

        return {
            "vision_result": vision_text or "Vision analysis unavailable.",
            "ocr_text": ocr_text,
            "combined_summary": summary,
            "structured": extracted,
            "signals": signals,
        }

    async def _analyze_vision(self, image_path: str) -> str:
        try:
            vr = await self.ai_service.vision(
                image_path,
                "List every scam indicator visible in this image in 2 short bullet points.",
            )
            if vr and "does not support image input" not in vr and "cannot read" not in vr.lower():
                return vr
        except Exception:
            pass
        return ""

    def _extract_structured(self, image_path: str) -> dict:
        result = {
            "text": "",
            "urls": [],
            "phones": [],
            "emails": [],
            "payments": [],
            "otps": [],
            "buttons": [],
            "suspicious_phrases": [],
            "bounding_boxes": [],
        }
        try:
            img = Image.open(image_path)
            result["text"] = pytesseract.image_to_string(img) or ""

            data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
            n = len(data.get("text", []))
            for i in range(n):
                word = (data["text"][i] or "").strip()
                if not word:
                    continue
                x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
                if self._is_url(word):
                    result["urls"].append(word)
                    result["bounding_boxes"].append({"type": "url", "text": word, "x": x, "y": y, "w": w, "h": h})
                elif self._is_phone(word):
                    result["phones"].append(word)
                    result["bounding_boxes"].append({"type": "phone", "text": word, "x": x, "y": y, "w": w, "h": h})
                elif self._is_email(word):
                    result["emails"].append(word)
                    result["bounding_boxes"].append({"type": "email", "text": word, "x": x, "y": y, "w": w, "h": h})
                elif self._is_payment(word):
                    result["payments"].append(word)
                    result["bounding_boxes"].append({"type": "payment", "text": word, "x": x, "y": y, "w": w, "h": h})
                elif self._is_otp(word):
                    result["otps"].append(word)
                    result["bounding_boxes"].append({"type": "otp", "text": word, "x": x, "y": y, "w": w, "h": h})
                elif self._is_button(word):
                    result["buttons"].append(word)
                    result["bounding_boxes"].append({"type": "button", "text": word, "x": x, "y": y, "w": w, "h": h})
                elif self._is_suspicious(word):
                    result["suspicious_phrases"].append(word)
                    result["bounding_boxes"].append({"type": "suspicious", "text": word, "x": x, "y": y, "w": w, "h": h})
        except Exception:
            pass
        return result

    def _detect_signals(self, ocr_text: str, vision_text: str, structured: dict) -> List[Dict[str, Any]]:
        signals = []
        text = f"{ocr_text} {vision_text}".lower()

        urgency_terms = ["urgent", "immediately", "asap", "act now", "limited time", "expires", "hurry", "verify immediately", "account suspended"]
        financial_terms = ["pay now", "transfer money", "processing fee", "payment required", "claim reward", "send money", "wire", "bitcoin", "crypto", "bank account", "fee", "invoice"]
        credential_terms = ["password", "otp", "pin", "verification code", "login details", "confirm your", "update your account", "security code"]
        impersonation_terms = ["bank", "government", "paypal", "google", "microsoft", "netflix", "official", "support", "account department", "irs"]
        reward_terms = ["winner", "prize", "won", "selected", "congratulations", "free money", "lottery", "inheritance", "reward", "exclusive offer"]

        def add_signal(category, terms, weight, evidence_texts):
            for term in terms:
                if term in text:
                    signals.append({
                        "category": category,
                        "score": weight,
                        "matched_terms": evidence_texts,
                        "confidence": min(0.99, max(0.6, weight + 0.1)),
                    })
                    break

        add_signal("urgency", urgency_terms, 0.9, [t for t in urgency_terms if t in text][:5])
        add_signal("financial_request", financial_terms, 0.95, [t for t in financial_terms if t in text][:5])
        add_signal("credential_request", credential_terms, 0.9, [t for t in credential_terms if t in text][:5])
        add_signal("impersonation", impersonation_terms, 0.8, [t for t in impersonation_terms if t in text][:5])
        add_signal("suspicious_promise", reward_terms, 0.85, [t for t in reward_terms if t in text][:5])

        if structured.get("payments"):
            add_signal("financial_request", ["payment request detected"], 0.9, structured["payments"][:3])
        if structured.get("otps"):
            add_signal("credential_request", ["otp request detected"], 0.9, structured["otps"][:3])
        if structured.get("phones") or structured.get("emails"):
            add_signal("credential_request", ["contact info request"], 0.6, (structured.get("phones", []) + structured.get("emails", []))[:3])

        return signals

    def _build_summary(self, signals: List[Dict[str, Any]], vision_text: str, ocr_text: str) -> str:
        if not signals and not vision_text and not ocr_text.strip():
            return "No readable content detected in the image. Analysis inconclusive; treat as suspicious."

        categories = [s["category"].replace("_", " ").title() for s in signals]
        if categories:
            unique = list(dict.fromkeys(categories))
            cat_text = ", ".join(unique[:-1])
            if len(unique) > 1:
                cat_text += f" and {unique[-1]}"
            else:
                cat_text = unique[0]
            return f"This image contains {cat_text} patterns. {len(unique)} fraud indicator{'s' if len(unique) != 1 else ''} detected. Treat this content as suspicious and verify through official channels."
        if vision_text and "unavailable" not in vision_text.lower():
            return f"Vision analysis: {vision_text[:180]}"
        if ocr_text.strip():
            return f"Image contains text but no strong scam patterns were automatically detected. Manual review recommended."
        return "Image analysis incomplete. Exercise caution with this content."

    def _is_url(self, text: str) -> bool:
        return bool(re.search(r"https?://|www\\.|bit\\.ly|tinyurl|t\\.co|goo\\.gl", text, re.IGNORECASE))

    def _is_phone(self, text: str) -> bool:
        return bool(re.search(r"\+?\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,4}[\s-]?\d{3,4}", text))

    def _is_email(self, text: str) -> bool:
        return bool(re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", text))

    def _is_payment(self, text: str) -> bool:
        return bool(re.search(r"pay|payment|fee|transfer|wire|bitcoin|crypto|bank account|invoice|charge|billing", text, re.IGNORECASE))

    def _is_otp(self, text: str) -> bool:
        return bool(re.search(r"otp|one.time code|verification code|pin|security code|cvv|\\b\\d{4,8}\\b", text, re.IGNORECASE))

    def _is_button(self, text: str) -> bool:
        return bool(re.search(r"click here|submit|verify|confirm|login|sign in|continue|accept|agree|download", text, re.IGNORECASE))

    def _is_suspicious(self, text: str) -> bool:
        return bool(re.search(r"suspend|block|limited|verify|urgent|immediate|action required|final notice|legal|court|irs|police", text, re.IGNORECASE))
