from app.models.scan import RiskLevel, ScanStatus
from app.models.advanced import ThreatCategory
from app.services.text_analyzer import TextAnalyzer
from app.services.ai_service import AIService
from app.services.image_analyzer import ImageAnalyzer
from app.services.advanced_analysis import AdvancedAnalysisService
from app.models.indicator import Indicator
from app.models.evidence import Evidence
from app.ml.scam_classifier import ScamClassifier
from app.ml.image_classifier import ImageClassifier
import uuid


class RiskEngine:
    def __init__(self):
        self.text_analyzer = TextAnalyzer()
        self.ai_service = AIService()
        self.image_analyzer = ImageAnalyzer()
        self.advanced_service = AdvancedAnalysisService()
        self.ml_classifier = ScamClassifier()
        self.dl_image_classifier = ImageClassifier()

    async def analyze_text(self, text: str, scan_id: uuid.UUID, db=None) -> dict:
        analysis = self.text_analyzer.analyze(text)
        rule_score = analysis["risk_score"]

        try:
            ml_result = self.ml_classifier.predict(text)
            ml_score = ml_result["risk_score"]
            ml_label = ml_result["label"]
        except Exception:
            ml_score = 0.0
            ml_label = "unknown"

        risk_score = max(rule_score, min(100.0, ml_score))
        risk_level = self._score_to_level(risk_score)

        indicators = []
        evidence = []

        for signal in analysis["signals"]:
            severity = int(signal["score"] * 100)
            confidence = min(0.99, max(0.5, signal["score"] + 0.1))
            detected_text = ", ".join(signal["matched_terms"][:5])

            indicator = Indicator(
                scan_id=scan_id,
                category=signal["category"].replace("_", " ").title(),
                title=f"{signal['category'].replace('_', ' ').title()} detected",
                description=f"Patterns associated with {signal['category'].replace('_', ' ')} were identified.",
                severity=severity,
                confidence=confidence,
                detected_text=detected_text,
            )
            indicators.append(indicator)

            evidence.append(Evidence(
                scan_id=scan_id,
                indicator_id=indicator.id if db is None else None,
                evidence_type="text_pattern",
                description=f"Matched terms: {detected_text}",
                confidence=confidence,
            ))

        system_prompt = (
            "You are ScamShield AI. Explain scam risk in 1 short sentence. "
            "Be concise. Do not claim certainty."
        )
        ai_summary = await self.ai_service.chat(
            f"Analyze this message. Risk score: {risk_score}/100, level: {risk_level}. "
            f"Signals: {', '.join(s['category'] for s in analysis['signals'])}. "
            f"Text: {text[:1500]}",
            system_prompt=system_prompt,
        )

        if not ai_summary or "unavailable" in ai_summary.lower():
            signal_count = len(analysis["signals"])
            ai_summary = f"{risk_level} risk detected with {signal_count} suspicious signal{'s' if signal_count != 1 else ''}."

        if ml_label != "unknown":
            ai_summary = f"[ML: {ml_label} {int(ml_score)}%] " + ai_summary

        max_len = 200
        if len(ai_summary) > max_len:
            ai_summary = ai_summary[:max_len].rstrip() + "..."

        recommendations = [
            "Do not send money or credentials.",
            "Verify the sender through an independently obtained official contact method.",
            "Treat this message as suspicious until proven otherwise.",
        ]

        if db is not None:
            try:
                language = self.advanced_service.detect_language(text)
                category = self._categorize_threat(analysis)
                for ind in indicators:
                    db.add(ind)
                for ev in evidence:
                    db.add(ev)
                db.commit()

                self.advanced_service.generate_scam_dna(db, scan_id, text, indicators)
                self.advanced_service.generate_threat_timeline(db, scan_id, risk_level, indicators)

                from app.models.scan import Scan
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.language = language
                    scan.primary_category = category
                    scan.confidence_score = round(sum(ind.confidence for ind in indicators) / len(indicators), 2) if indicators else 0.5
                    db.commit()

                user_id = scan.user_id if scan else None
                if user_id and category:
                    self.advanced_service.update_category_stats(db, user_id, category, risk_score)
            except Exception:
                db.rollback()

        max_len = 300
        if len(ai_summary) > max_len:
            ai_summary = ai_summary[:max_len].rstrip() + "..."

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": ai_summary,
            "indicators": indicators,
            "evidence": evidence,
            "recommendations": recommendations,
            "status": ScanStatus.COMPLETED,
            "ml_analysis": {
                "model_type": self.ml_classifier.model_type,
                "label": ml_label,
                "probability": round(ml_score, 2),
                "features_used": "TF-IDF + Random Forest",
            },
        }

    async def analyze_image(self, image_path: str, scan_id: uuid.UUID, db=None) -> dict:
        image_result = await self.image_analyzer.analyze(image_path, scan_id)
        vision_text = image_result.get("vision_result", "") or ""
        ocr_text = image_result.get("ocr_text") or ""
        structured = image_result.get("structured", {}) or {}
        signals = image_result.get("signals", []) or []
        combined_text = f"{vision_text}\n{ocr_text}".strip()

        text_analysis = self.text_analyzer.analyze(combined_text) if combined_text else {"risk_score": 0.0, "signals": []}
        all_signals = signals + text_analysis["signals"]

        seen = set()
        unique_signals = []
        for s in all_signals:
            key = s["category"]
            if key not in seen:
                seen.add(key)
                unique_signals.append(s)

        weights = {
            "urgency": 20,
            "credential_request": 25,
            "financial_request": 25,
            "impersonation": 15,
            "suspicious_promise": 15,
            "suspicious_url": 10,
        }
        weighted_sum = 0.0
        total_weight = 0.0
        for s in unique_signals:
            w = weights.get(s["category"], 10)
            weighted_sum += s["score"] * 100 * w
            total_weight += w
        base_score = weighted_sum / total_weight if total_weight > 0 else 0.0

        vision_has_content = vision_text.strip() and "unavailable" not in vision_text.lower() and "no clear scam" not in vision_text.lower()
        ocr_has_content = bool(ocr_text.strip())

        if not unique_signals:
            if not ocr_has_content and not vision_has_content:
                base_score = max(base_score, 38.0)
            elif ocr_has_content or vision_has_content:
                base_score = max(base_score, 28.0)

        try:
            dl_result = self.dl_image_classifier.predict(image_path)
            dl_score = dl_result.get("risk_score", 0.0)
            if dl_score > base_score:
                base_score = dl_score
        except Exception:
            dl_result = {"label": "unknown", "confidence": 0.0, "risk_score": 0.0}

        base_score = max(0.0, min(100.0, base_score))
        risk_level = self._score_to_level(base_score)

        indicators = []
        evidence = []

        vision_indicator = Indicator(
            scan_id=scan_id,
            category="Image Analysis",
            title="AI vision assessment",
            description=image_result.get("combined_summary") or "Screenshot analyzed.",
            severity=int(max(20, min(90, base_score))),
            confidence=max(0.4, min(0.95, base_score / 100.0)),
            detected_text=ocr_text[:500] if ocr_text else None,
        )
        indicators.append(vision_indicator)
        evidence.append(Evidence(
            scan_id=scan_id,
            indicator_id=vision_indicator.id,
            evidence_type="vision",
            description="Screenshot analyzed by vision model.",
            confidence=vision_indicator.confidence,
        ))

        for signal in unique_signals:
            severity = int(signal["score"] * 100)
            confidence = min(0.99, max(0.5, signal["score"] + 0.1))
            detected_text = ", ".join(signal.get("matched_terms", [])[:5])
            indicator = Indicator(
                scan_id=scan_id,
                category=signal["category"].replace("_", " ").title(),
                title=f"{signal['category'].replace('_', ' ').title()} detected",
                description=f"Patterns associated with {signal['category'].replace('_', ' ')} were identified in the image.",
                severity=severity,
                confidence=confidence,
                detected_text=detected_text,
            )
            indicators.append(indicator)
            evidence.append(Evidence(
                scan_id=scan_id,
                indicator_id=indicator.id,
                evidence_type="ocr_text_pattern",
                description=f"Matched terms: {detected_text}",
                confidence=confidence,
            ))

        if structured.get("payments"):
            evidence.append(Evidence(
                scan_id=scan_id,
                indicator_id=None,
                evidence_type="payment_request",
                description=f"Payment request detected: {', '.join(structured['payments'][:3])}",
                confidence=0.85,
            ))
        if structured.get("otps"):
            evidence.append(Evidence(
                scan_id=scan_id,
                indicator_id=None,
                evidence_type="otp_request",
                description=f"OTP request detected: {', '.join(structured['otps'][:3])}",
                confidence=0.85,
            ))
        if structured.get("urls"):
            evidence.append(Evidence(
                scan_id=scan_id,
                indicator_id=None,
                evidence_type="suspicious_url",
                description=f"URL detected: {', '.join(structured['urls'][:3])}",
                confidence=0.7,
            ))
        if structured.get("phones"):
            evidence.append(Evidence(
                scan_id=scan_id,
                indicator_id=None,
                evidence_type="contact_request",
                description=f"Phone number detected: {', '.join(structured['phones'][:3])}",
                confidence=0.7,
            ))
        if structured.get("emails"):
            evidence.append(Evidence(
                scan_id=scan_id,
                indicator_id=None,
                evidence_type="contact_request",
                description=f"Email detected: {', '.join(structured['emails'][:3])}",
                confidence=0.7,
            ))

        if db is not None:
            try:
                for ind in indicators:
                    db.add(ind)
                for ev in evidence:
                    db.add(ev)
                db.commit()

                from app.models.advanced import ScreenshotIntelligence
                screenshot_intel = ScreenshotIntelligence(
                    scan_id=scan_id,
                    ocr_text=ocr_text or None,
                    suspicious_areas=[b for b in structured.get("bounding_boxes", []) if b.get("type") == "suspicious"],
                    bounding_boxes=structured.get("bounding_boxes", []),
                    detected_buttons=structured.get("buttons", []),
                    detected_warnings=structured.get("suspicious_phrases", []),
                    payment_requests=structured.get("payments", []),
                )
                db.add(screenshot_intel)
                db.commit()

                self.advanced_service.generate_scam_dna(db, scan_id, combined_text, indicators)
                self.advanced_service.generate_threat_timeline(db, scan_id, risk_level, indicators)

                from app.models.scan import Scan
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    language = self.advanced_service.detect_language(combined_text)
                    scan.language = language
                    scan.confidence_score = round(sum(ind.confidence for ind in indicators) / len(indicators), 2) if indicators else 0.5
                    category = self._categorize_threat({"signals": unique_signals})
                    scan.primary_category = category
                    db.commit()

                user_id = scan.user_id if scan else None
                category = scan.primary_category if scan else None
                if user_id and category:
                    self.advanced_service.update_category_stats(db, user_id, category, base_score)
            except Exception:
                db.rollback()

        summary = image_result.get("combined_summary") or "Screenshot analyzed."
        if "no readable content" in summary.lower() and base_score > 0:
            summary = f"{risk_level} risk detected with {len(unique_signals)} suspicious signal{'s' if len(unique_signals) != 1 else ''} in the image."
        max_len = 200
        if len(summary) > max_len:
            summary = summary[:max_len].rstrip() + "..."

        return {
            "risk_score": round(base_score, 1),
            "risk_level": risk_level,
            "summary": summary,
            "indicators": indicators,
            "evidence": evidence,
            "recommendations": [
                "Do not interact with suspicious content in the screenshot.",
                "Verify any requests through official channels.",
            ],
            "status": ScanStatus.COMPLETED,
            "dl_analysis": {
                "model": "MobileNetV2",
                "framework": "PyTorch",
                "prediction": dl_result.get("label", "unknown"),
                "confidence": dl_result.get("confidence", 0.0),
            },
        }

    def _score_to_level(self, score: float) -> RiskLevel:
        if score < 30:
            return RiskLevel.SAFE
        if score < 60:
            return RiskLevel.SUSPICIOUS
        if score < 80:
            return RiskLevel.HIGH_RISK
        return RiskLevel.CRITICAL

    def _categorize_threat(self, analysis: dict) -> ThreatCategory:
        signals = analysis.get("signals", [])
        categories = [s["category"] for s in signals]

        if any("phish" in c for c in categories):
            return ThreatCategory.PHISHING
        if any("financial" in c or "payment" in c for c in categories):
            return ThreatCategory.BANKING_SCAM
        if any("job" in c or "employment" in c for c in categories):
            return ThreatCategory.JOB_SCAM
        if any("prize" in c or "lottery" in c or "winner" in c for c in categories):
            return ThreatCategory.PRIZE_SCAM
        if any("crypto" in c or "bitcoin" in c for c in categories):
            return ThreatCategory.CRYPTO_SCAM
        if any("social" in c or "impersonation" in c for c in categories):
            return ThreatCategory.SOCIAL_ENGINEERING
        return ThreatCategory.OTHER

