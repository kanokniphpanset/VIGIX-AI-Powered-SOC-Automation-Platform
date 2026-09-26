"""ML severity classifier (graph node "ml_risk", name kept for LangGraph state/checkpoint compatibility).

Thin wrapper: build features -> model -> SEVERITY suggestion (low..critical) + confidence -> AgentState.
Not an LLM agent. The model's internal numeric output is used ONLY inside this node to pick the severity band;
it is never written to the graph state, persisted, sent to the backend or used by any decision: Severity is
VIGIX's primary classification and a human analyst validates it.

XGBoost is the primary model. WeightedRiskModel is the transparent
fallback so the pipeline can continue if XGBoost initialization or
prediction fails.
"""

from __future__ import annotations

from src.contracts.error_builder import build_error
from src.graph.state import AgentState

from .feature_engineering import build_features
from .schema import RiskResult
from src.ml_models.xgboost_provider import (
    MODEL_VERSION as XGBOOST_MODEL_VERSION,
    XgboostRiskModel,
)
from src.ml_models.weighted_risk_model import (
    MODEL_VERSION as WEIGHTED_MODEL_VERSION,
    WeightedRiskModel,
)


_xgboost_model: XgboostRiskModel | None = None
_weighted_model: WeightedRiskModel | None = None


def _get_xgboost_model() -> XgboostRiskModel:
    global _xgboost_model

    if _xgboost_model is None:
        _xgboost_model = XgboostRiskModel()

    return _xgboost_model


def _get_weighted_model() -> WeightedRiskModel:
    global _weighted_model

    if _weighted_model is None:
        _weighted_model = WeightedRiskModel()

    return _weighted_model


def _prediction_to_result(
    prediction: dict,
    features: dict[str, float],
    model_version: str,
) -> RiskResult:
    """Convert provider output into the shared RiskResult schema."""

    score = int(round(float(prediction["risk_score"])))

    severity = str(prediction["severity_prediction"]).upper()

    return RiskResult(
        score=score,
        level=severity,
        features=features,
        model_version=model_version,
    )


def run_ml_risk(features: dict[str, float]) -> RiskResult:
    """Run the primary XGBoost model with WeightedRiskModel fallback."""

    try:
        prediction = _get_xgboost_model().predict(features)

        return _prediction_to_result(
            prediction=prediction,
            features=features,
            model_version=XGBOOST_MODEL_VERSION,
        )

    except Exception:
        prediction = _get_weighted_model().predict(features)

        return _prediction_to_result(
            prediction=prediction,
            features=features,
            model_version=WEIGHTED_MODEL_VERSION,
        )


async def run(state: AgentState) -> AgentState:
    """LangGraph ML risk node."""

    try:
        features = build_features(state)

        result = run_ml_risk(features)

        # Preserve the provider's confidence value because it is useful
        # downstream even though RiskResult itself does not expose it.
        try:
            prediction = _get_xgboost_model().predict(features)

        except Exception:
            prediction = _get_weighted_model().predict(features)

        return {
            "severity_prediction": result.level.lower(),
            "confidence_score": float(prediction["confidence_score"]),
            "ml_model_version": result.model_version,
            "severity_classification": {
                "severity": result.level.upper(),
                "confidence": float(prediction["confidence_score"]),
                "model_version": result.model_version,
                "features": result.features,
            },
            "trace": [
                (
                    f"MlSeverityClassifier: model={result.model_version}, "
                    f"severity={result.level}, "
                    f"confidence={prediction['confidence_score']}"
                )
            ],
        }

    except Exception as exc:
        error = build_error(
            agent="ml_risk",
            code="AGENT_EXECUTION_FAILED",
            message=f"ML risk agent failed: {exc}",
            retryable=True,
            severity="ERROR",
        )

        # No severity is invented on failure (it used to default to "low"): the analyst classifies it.
        return {
            "severity_prediction": None,
            "confidence_score": 0.0,
            "ml_model_version": "",
            "structured_errors": [
                error.model_dump(by_alias=True, mode="json")
            ],
            "trace": [
                f"MlRiskAgent: execution failed ({type(exc).__name__})"
            ],
        }
