
import os
from datetime import datetime, timezone

from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory
)
from flask_cors import CORS

from simulation import get_simulation_events
from detection import analyze_event
from models import (
    db,
    Simulation,
    SecurityEvent,
    AlertStatus
)


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__)
CORS(app)

os.makedirs(app.instance_path, exist_ok=True)

database_path = os.path.join(
    app.instance_path,
    "kaseya_defense.db"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + database_path.replace("\\", "/")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

print("SQLite database connected successfully!")


events = get_simulation_events()
current_index = 0
current_risk = 0
current_simulation_id = None


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def finish_active_simulation(status):
    global current_simulation_id

    if current_simulation_id is None:
        return

    simulation = db.session.get(
        Simulation,
        current_simulation_id
    )

    if simulation and simulation.status == "RUNNING":
        simulation.status = status
        simulation.ended_at = utc_now()
        db.session.commit()

    current_simulation_id = None


# ==========================================
# FRONTEND
# ==========================================

@app.route("/")
def home():
    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


@app.route("/<path:filename>")
def serve_frontend(filename):
    return send_from_directory(
        FRONTEND_DIR,
        filename
    )


# ==========================================
# HEALTH
# ==========================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "Backend running successfully",
        "database": "SQLite connected"
    })


# ==========================================
# START SIMULATION
# ==========================================

@app.route("/api/simulation/start", methods=["POST"])
def start_simulation():
    global current_index
    global current_risk
    global current_simulation_id

    finish_active_simulation("INTERRUPTED")

    current_index = 0
    current_risk = 0

    simulation = Simulation(
        status="RUNNING",
        final_risk_score=0,
        final_threat_level="LOW"
    )

    db.session.add(simulation)
    db.session.commit()

    current_simulation_id = simulation.id

    return jsonify({
        "message": "Simulation started successfully",
        "simulation_id": simulation.id,
        "total_events": len(events)
    })


# ==========================================
# NEXT SIMULATION EVENT
# ==========================================

@app.route("/api/simulation/next", methods=["POST"])
def next_event():
    global current_index
    global current_risk
    global current_simulation_id

    if current_index >= len(events):
        finish_active_simulation("COMPLETED")

        return jsonify({
            "completed": True,
            "message": "Simulation completed",
            "risk_score": current_risk,
            "progress": current_index
        })

    if current_simulation_id is None:
        return jsonify({
            "error": "Start a simulation first"
        }), 400

    event = events[current_index]

    result = analyze_event(event, current_risk)

    current_risk = int(result["risk_score"])
    threat_level = str(result["threat_level"])

    current_index += 1

    simulation = db.session.get(
        Simulation,
        current_simulation_id
    )

    saved_event = SecurityEvent(
        simulation_id=current_simulation_id,
        event_name=str(
            event.get("name", "Unknown Event")
        ),
        source=str(
            event.get("source", "Unknown")
        ),
        severity=str(
            event.get("severity", "LOW")
        ),
        risk_score=current_risk,
        threat_level=threat_level,
        progress=current_index,
        event_data=event
    )

    db.session.add(saved_event)

    simulation.final_risk_score = current_risk
    simulation.final_threat_level = threat_level

    simulation_id = current_simulation_id

    if current_index >= len(events):
        simulation.status = "COMPLETED"
        simulation.ended_at = utc_now()
        current_simulation_id = None

    db.session.commit()

    return jsonify({
        "completed": False,
        "simulation_id": simulation_id,
        "event": event,
        "risk_score": current_risk,
        "threat_level": threat_level,
        "progress": current_index
    })


# ==========================================
# RESET SIMULATION
# ==========================================

@app.route("/api/simulation/reset", methods=["POST"])
def reset_simulation():
    global current_index
    global current_risk

    finish_active_simulation("RESET")

    current_index = 0
    current_risk = 0

    return jsonify({
        "message": "Simulation reset successfully",
        "risk_score": 0,
        "threat_level": "LOW"
    })


# ==========================================
# SIMULATION HISTORY
# ==========================================

@app.route("/api/simulations", methods=["GET"])
def list_simulations():
    simulations = Simulation.query.order_by(
        Simulation.id.desc()
    ).all()

    return jsonify({
        "total": len(simulations),
        "simulations": [
            simulation.to_dict()
            for simulation in simulations
        ]
    })


@app.route(
    "/api/simulations/<int:simulation_id>",
    methods=["GET"]
)
def get_simulation(simulation_id):
    simulation = db.get_or_404(
        Simulation,
        simulation_id
    )

    result = simulation.to_dict()

    result["events"] = [
        event.to_dict()
        for event in simulation.events
    ]

    return jsonify(result)


# ==========================================
# SAVED EVENTS
# ==========================================

@app.route("/api/events", methods=["GET"])
def get_saved_events():
    saved_events = SecurityEvent.query.order_by(
        SecurityEvent.id.desc()
    ).all()

    return jsonify({
        "total": len(saved_events),
        "events": [
            event.to_dict()
            for event in saved_events
        ]
    })


# ==========================================
# ALERTS API
# ==========================================

@app.route("/api/alerts", methods=["GET"])
def get_security_alerts():
    saved_events = SecurityEvent.query.order_by(
        SecurityEvent.id.desc()
    ).all()

    saved_statuses = {
        item.security_event_id: item.status
        for item in AlertStatus.query.all()
    }

    alerts = []

    for event in saved_events:
        severity = str(
            event.severity or "LOW"
        ).upper()

        if severity not in [
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ]:
            continue

        alerts.append({
            "id": event.id,
            "simulation_id": event.simulation_id,
            "title": event.event_name,
            "source": event.source,
            "severity": severity,
            "risk_score": event.risk_score,
            "threat_level": event.threat_level,
            "timestamp": (
                event.timestamp.isoformat() + "Z"
            ),
            "status": saved_statuses.get(
                event.id,
                "NEW"
            )
        })

    return jsonify({
        "total": len(alerts),
        "new": sum(
            alert["status"] == "NEW"
            for alert in alerts
        ),
        "acknowledged": sum(
            alert["status"] == "ACKNOWLEDGED"
            for alert in alerts
        ),
        "resolved": sum(
            alert["status"] == "RESOLVED"
            for alert in alerts
        ),
        "alerts": alerts
    })


# ==========================================
# UPDATE ALERT STATUS
# ==========================================

@app.route(
    "/api/alerts/<int:alert_id>/status",
    methods=["PATCH"]
)
def update_alert_status(alert_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "JSON object required"
        }), 400

    new_status = str(
        data.get("status", "")
    ).upper()

    allowed_statuses = [
        "NEW",
        "ACKNOWLEDGED",
        "RESOLVED"
    ]

    if new_status not in allowed_statuses:
        return jsonify({
            "error": "Invalid alert status"
        }), 400

    event = db.session.get(
        SecurityEvent,
        alert_id
    )

    if event is None:
        return jsonify({
            "error": "Alert not found"
        }), 404

    severity = str(
        event.severity or "LOW"
    ).upper()

    if severity not in [
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]:
        return jsonify({
            "error": "This event is not an alert"
        }), 404

    record = AlertStatus.query.filter_by(
        security_event_id=alert_id
    ).first()

    current_status = (
        record.status if record else "NEW"
    )

    transitions = {
        "NEW": "ACKNOWLEDGED",
        "ACKNOWLEDGED": "RESOLVED"
    }

    if transitions.get(current_status) != new_status:
        return jsonify({
            "error": (
                "Invalid status transition: "
                f"{current_status} to {new_status}"
            )
        }), 409

    if record is None:
        record = AlertStatus(
            security_event_id=alert_id,
            status=new_status
        )
        db.session.add(record)
    else:
        record.status = new_status

    db.session.commit()

    return jsonify({
        "message": "Alert status updated successfully",
        "alert_id": alert_id,
        "status": new_status
    })


# ==========================================
# RUN FLASK
# ==========================================

if __name__ == "__main__":
    app.run(debug=True, port=5000)
