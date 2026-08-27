from src.analyzers.correlation_engine import CorrelationEngine, calculate_risk_score

def test_risk_score_calculation():
    reasons = [
        "Multiple failed logins",
        "Suspicious download",
        "Executable execution",
        "Persistence detected"
    ]
    score, severity = calculate_risk_score(reasons)
    assert score == 87
    assert severity == "HIGH"

def test_correlation_engine_output():
    engine = CorrelationEngine()
    result = engine.correlate()
    assert "chain" in result
    assert result["risk_score"] == 87
    assert result["severity"] == "HIGH"
    assert len(result["reasons"]) == 4

def test_correlation_engine_display():
    engine = CorrelationEngine()
    display_str = engine.display()
    assert "SSH Brute Force" in display_str
    assert "↓" in display_str
    assert "Risk Score: 87/100" in display_str
    assert "Severity: HIGH" in display_str
    assert "+ Multiple failed logins" in display_str
