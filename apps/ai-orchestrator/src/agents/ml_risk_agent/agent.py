from src.graph.state import AgentState
from src.ml_models.xgboost_provider import XgboostRiskModel
from .feature_engineering import build_features

_model = XgboostRiskModel()


async def run(state: AgentState) -> AgentState:
    """
    MlRiskAgent — scores the incident with XGBoost using features derived from
    ThreatIntelAgent, MitreAgent, and RagAgent's outputs. The bundled model is
    bootstrap-trained on synthetic data (see xgboost_provider.py); retrain it
    on real closed-incident outcomes via FeedbackAgent once you have enough
    labeled history.
    """
    features = build_features(state)
    prediction = _model.predict(features)

    return {
        "risk_score": prediction["risk_score"],
        "severity_prediction": prediction["severity_prediction"],
        "confidence_score": prediction["confidence_score"],
        "trace": [
            f"MlRiskAgent: risk_score={prediction['risk_score']} "
            f"severity={prediction['severity_prediction']} confidence={prediction['confidence_score']}"
        ],
    }
