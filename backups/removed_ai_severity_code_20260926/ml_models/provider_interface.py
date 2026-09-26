from abc import ABC, abstractmethod
from typing import TypedDict


class RiskPrediction(TypedDict):
    risk_score: float  # 0-100
    severity_prediction: str  # low | medium | high | critical
    confidence_score: float  # 0-1


class IRiskModel(ABC):
    """Abstract risk model. MlRiskAgent depends only on this."""

    @abstractmethod
    def predict(self, features: dict[str, float]) -> RiskPrediction:
        raise NotImplementedError
