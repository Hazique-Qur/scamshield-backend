import os
import json
import random
from typing import List, Dict, Tuple

SCAM_EXAMPLES = [
    "urgent payment required immediately",
    "your account has been suspended verify now",
    "act now limited time offer expires today",
    "send money to this account immediately",
    "congratulations you have won a prize claim now",
    "verify your password and otp immediately",
    "urgent transfer money to avoid penalty",
    "your payment is pending confirm within 1 hour",
    "dear customer your account will be blocked",
    "click here to claim your reward now",
    "irs tax refund pending verify identity",
    "bank alert suspicious activity login now",
    "free money waiting claim your prize",
    "lottery winner selected collect reward",
    "update your payment details immediately",
    "security alert verify your account now",
    "your package delivery failed pay customs fee",
    "claim your inheritance money today",
    "limited offer no risk guaranteed return",
    "exclusive deal send bitcoin now",
    "urgent action required account verification",
    "verify your identity to avoid suspension",
    "you have been selected for cash reward",
    "processing fee required for refund",
    "immediate payment needed to prevent legal action",
]

NORMAL_EXAMPLES = [
    "hi how are you doing today",
    "can we meet tomorrow for coffee",
    "the meeting is scheduled for 10am",
    "please review the document i sent",
    "happy birthday hope you have a good day",
    "dinner last night was great",
    "can you send me the report by friday",
    "i will call you later tonight",
    "the project deadline is next week",
    "thank you for your help yesterday",
    "let me know when you are free",
    "the weather is nice today",
    "i finished my homework",
    "what time does the movie start",
    "please bring your laptop tomorrow",
    "good morning have a nice day",
    "see you at the office next monday",
    "did you watch the game last night",
    "i am going to the gym now",
    "let us have lunch together soon",
    "the concert was amazing last night",
    "can you recommend a good restaurant",
    "i need to buy some groceries",
    "the flight arrives at 6pm tomorrow",
    "please confirm your attendance",
]

EXTRA_NORMAL = [
    "hello professor class is cancelled today",
    "the library is open until 9pm",
    "i submitted my assignment on time",
    "family dinner at 7pm tonight",
    "the bus is running late today",
    "my friend is visiting this weekend",
    "the cafe near campus is good",
    "i finished reading that book you recommended",
    "the gym membership expired last month",
    "shall we go for a walk in the evening",
    "the train departs from platform 3",
    "i updated my email signature",
    "the new cafe serves great coffee",
    "let us plan the weekend trip",
    "the wifi password is on the notice board",
]

EXTRA_SCAM = [
    "urgent your bank account is compromised act now",
    "verify your ssn and bank details immediately",
    "you have unpaid taxes pay now to avoid arrest",
    "your paypal account is limited confirm identity",
    "claim your free gift card limited time only",
    "send btc now to receive double back",
    "your netflix account will be suspended verify now",
    "court summons pending call now to avoid arrest",
    "winner select your prize entry fee required",
    "urgent crypto investment opportunity limited spots",
    "immigration case pending pay processing fee",
    "your microsoft license is expired renew now",
    "insurance claim approved pay processing fee",
    "rent payment failed update card details now",
    "loan approved verify income and bank details",
]

LABEL_MAP = {"scam": 1, "not_scam": 0}


def build_dataset(split: float = 0.85) -> Tuple[List[str], List[int], List[str], List[int]]:
    texts: List[str] = []
    labels: List[int] = []

    for txt in SCAM_EXAMPLES + EXTRA_SCAM:
        texts.append(txt)
        labels.append(1)
    for txt in NORMAL_EXAMPLES + EXTRA_NORMAL:
        texts.append(txt)
        labels.append(0)

    combined = list(zip(texts, labels))
    random.seed(42)
    random.shuffle(combined)

    texts, labels = zip(*combined)
    texts = list(texts)
    labels = [int(l) for l in labels]

    n_train = int(len(texts) * split)
    train_texts = texts[:n_train]
    train_labels = labels[:n_train]
    test_texts = texts[n_train:]
    test_labels = labels[n_train:]

    return train_texts, train_labels, test_texts, test_labels


def save_dataset(path: str) -> None:
    train_texts, train_labels, test_texts, test_labels = build_dataset()
    data = {
        "train_texts": train_texts,
        "train_labels": train_labels,
        "test_texts": test_texts,
        "test_labels": test_labels,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    save_dataset("app/ml/dataset.json")
    print("Dataset saved to app/ml/dataset.json")
