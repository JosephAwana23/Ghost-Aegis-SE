import random

def get_behavior_score(keystrokes, mouse_movements):
    """
    Local heuristic engine to evaluate behavioral telemetry.
    Replaces the dummy external API endpoint with localized math.
    """
    try:
        avg_delay = keystrokes.get("avg_delay", 0.0)
        variance = keystrokes.get("variance", 0.0)
        speed = mouse_movements.get("speed", 0.0)
        jitter = mouse_movements.get("jitter", 0.0)
        
        # Baseline expectations (what a "normal" authorized user looks like)
        expected_delay = 0.15
        expected_speed = 1.2
        
        # Calculate deviation from the baseline
        delay_deviation = abs(expected_delay - avg_delay)
        speed_deviation = abs(expected_speed - speed)
        
        # Calculate base risk score (0 to 100)
        # Heavy weight on keystroke variance and mouse jitter (bot-like behavior)
        risk_score = (delay_deviation * 100) + (variance * 200) + (speed_deviation * 20) + (jitter * 100)
        
        # Add a tiny variance so the score fluctuates naturally during testing
        risk_score += random.uniform(-3.0, 3.0)
        
        # Clamp the final score between 0 and 100
        final_score = max(0, min(100, int(risk_score)))
        
        # Determine threat level
        if final_score < 40:
            risk_level = "trusted"
        elif final_score < 75:
            risk_level = "suspicious"
        else:
            risk_level = "malicious"
            
        return {
            "score": final_score,
            "risk": risk_level
        }
        
    except Exception as e:
        return {"error": str(e)}