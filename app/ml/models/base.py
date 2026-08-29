from typing import Any


class BaseModel:
    def fit(self, X: Any, y: Any):
        raise NotImplementedError

    def predict(self, X: Any) -> Any:
        raise NotImplementedError
