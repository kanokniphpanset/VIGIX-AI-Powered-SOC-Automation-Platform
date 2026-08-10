def maybe_trigger_retrain(feedback_count_since_last_retrain: int, threshold: int = 100) -> bool:
    """
    Decides whether enough new analyst feedback has accumulated to justify
    retraining the XGBoost risk model. Returns True/False rather than actually
    retraining inline — retraining is a separate offline job (see
    docs/architecture "Future Scalability") that should run out-of-band, not
    block the request/response pipeline.
    """
    return feedback_count_since_last_retrain >= threshold
