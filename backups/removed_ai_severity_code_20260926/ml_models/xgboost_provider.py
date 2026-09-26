# Re-activated as MlRiskAgent's PRIMARY model (see ml_risk_agent/agent.py) —
# explicit decision, not a reversal of Phase 12's reasoning: Phase 12 turned
# this off because it's bootstrap-trained on synthetic data (see
# _bootstrap_training_data() below), not real labeled incident history, and
# a tree ensemble is harder to explain than a transparent weighted sum.
# Both of those facts are still true — nothing about the model itself
# changed. WeightedRiskModel (weighted_risk_model.py) is now the FALLBACK,
# used automatically if this model's init/predict ever raises (see
# ml_risk_agent/agent.py's try/except) — matching this codebase's existing
# "never crash the pipeline, degrade to something transparent" convention
# (see llm_analyst_agent's own Ollama-unavailable fallback). MODEL_VERSION
# below is what gets persisted per-run — a run that actually fell back
# still correctly persists weighted_risk_model.MODEL_VERSION, not this one.
import numpy as np
import xgboost as xgb
from .provider_interface import IRiskModel, RiskPrediction

MODEL_VERSION = "xgboost-bootstrap-v1"

FEATURE_ORDER = [
    "ioc_count",
    "ioc_avg_reputation",
    "mitre_technique_count",
    "rag_document_count",
    "siem_severity_numeric",  # low=1 medium=2 high=3 critical=4
]


def _bootstrap_training_data(n: int = 400) -> tuple[np.ndarray, np.ndarray]:
    """
    Generates a synthetic training set that encodes the intuitive relationship
    "more/worse evidence -> higher risk" so the model is directionally sane
    out of the box. Replace this with FeedbackAgent-sourced historical incident
    outcomes once real labeled data accumulates (see agents/feedback_agent).
    """
    rng = np.random.default_rng(42)
    X = rng.uniform(0, 1, size=(n, len(FEATURE_ORDER)))
    X[:, 0] *= 10  # ioc_count 0-10
    X[:, 1] *= 100  # ioc_avg_reputation 0-100
    X[:, 2] *= 6  # mitre_technique_count 0-6
    X[:, 3] *= 5  # rag_document_count 0-5
    X[:, 4] = rng.integers(1, 5, size=n)  # siem_severity_numeric 1-4

    weights = np.array([0.15, 0.35, 0.15, 0.05, 0.30])
    normalized = X / np.array([10, 100, 6, 5, 4])
    y = normalized @ weights * 100 + rng.normal(0, 5, size=n)
    y = np.clip(y, 0, 100)
    return X, y


class XgboostRiskModel(IRiskModel):
    """
    Bootstrap-trains an XGBoost regressor in memory on every process start.
    Deliberately does NOT persist to disk via save_model()/load_model() —
    XGBoost's sklearn wrapper round-trip has known breakage across
    xgboost/scikit-learn version combinations (the wrapper calls
    scikit-learn's is_classifier()/get_tags() internals, which changed
    shape in scikit-learn 1.6). Training on 400 synthetic rows takes well
    under a second, so there's no real cost to just doing it fresh each time.

    Once real labeled incident outcomes accumulate (via FeedbackAgent),
    replace _bootstrap_training_data() with a query against analyst_feedback
    and closed incidents — the persistence question can be revisited then
    (e.g. pickle the raw Booster with xgb.Booster.save_model, which doesn't
    go through the sklearn-compatibility layer that's breaking here).
    """

    def __init__(self):
        self.model = xgb.XGBRegressor(n_estimators=80, max_depth=4, learning_rate=0.1)
        X, y = _bootstrap_training_data()
        self.model.fit(X, y)

    def predict(self, features: dict[str, float]) -> RiskPrediction:
        vector = np.array([[features.get(f, 0.0) for f in FEATURE_ORDER]])
        raw_score = float(self.model.predict(vector)[0])
        score = max(0.0, min(100.0, raw_score))

        if score >= 75:
            severity = "critical"
        elif score >= 50:
            severity = "high"
        elif score >= 25:
            severity = "medium"
        else:
            severity = "low"

        # Confidence heuristic: more IOC/MITRE/RAG evidence -> more confident prediction.
        evidence = features.get("ioc_count", 0) + features.get("mitre_technique_count", 0) * 2
        confidence = min(0.95, 0.4 + evidence * 0.05)

        return {"risk_score": round(score, 2), "severity_prediction": severity, "confidence_score": round(confidence, 2)}
