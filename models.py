
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Simulation(db.Model):
    __tablename__ = "simulations"

    id = db.Column(db.Integer, primary_key=True)
    started_at = db.Column(
        db.DateTime, default=utc_now, nullable=False
    )
    ended_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(
        db.String(20), default="RUNNING", nullable=False
    )
    final_risk_score = db.Column(
        db.Integer, default=0, nullable=False
    )
    final_threat_level = db.Column(
        db.String(20), default="LOW", nullable=False
    )

    events = db.relationship(
        "SecurityEvent",
        back_populates="simulation",
        cascade="all, delete-orphan",
        order_by="SecurityEvent.id"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "started_at": self.started_at.isoformat() + "Z",
            "ended_at": (
                self.ended_at.isoformat() + "Z"
                if self.ended_at else None
            ),
            "status": self.status,
            "final_risk_score": self.final_risk_score,
            "final_threat_level": self.final_threat_level,
            "event_count": len(self.events)
        }


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)

    simulation_id = db.Column(
        db.Integer,
        db.ForeignKey("simulations.id"),
        nullable=False,
        index=True
    )

    event_name = db.Column(db.String(200), nullable=False)
    source = db.Column(db.String(200), default="Unknown")
    severity = db.Column(db.String(30), default="LOW")
    risk_score = db.Column(db.Integer, default=0)
    threat_level = db.Column(db.String(20), default="LOW")
    progress = db.Column(db.Integer, default=0)
    event_data = db.Column(db.JSON, nullable=False)

    timestamp = db.Column(
        db.DateTime, default=utc_now, nullable=False
    )

    simulation = db.relationship(
        "Simulation",
        back_populates="events"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "simulation_id": self.simulation_id,
            "event_name": self.event_name,
            "source": self.source,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "progress": self.progress,
            "event": self.event_data,
            "timestamp": self.timestamp.isoformat() + "Z"
        }


class AlertStatus(db.Model):
    __tablename__ = "alert_statuses"

    id = db.Column(db.Integer, primary_key=True)

    security_event_id = db.Column(
        db.Integer,
        db.ForeignKey("security_events.id"),
        unique=True,
        nullable=False
    )

    status = db.Column(
        db.String(20),
        default="NEW",
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime,
        default=utc_now,
        onupdate=utc_now,
        nullable=False
    )
