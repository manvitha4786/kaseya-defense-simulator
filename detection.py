# backend/detection.py


def calculate_threat(risk_score):

    if risk_score < 30:
        return "LOW"

    elif risk_score < 60:
        return "MEDIUM"

    elif risk_score < 80:
        return "HIGH"

    else:
        return "CRITICAL"


def analyze_event(event, current_risk):

    new_risk = min(
        100,
        current_risk + event["risk"]
    )

    threat_level = calculate_threat(new_risk)

    return {
        "risk_score": new_risk,
        "threat_level": threat_level
    }