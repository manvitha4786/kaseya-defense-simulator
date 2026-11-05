# backend/simulation.py

SIMULATION_EVENTS = [
    {
        "name": "Unusual administrator login",
        "source": "Admin Account",
        "severity": "Low",
        "risk": 10,
        "stage": 0
    },
    {
        "name": "Server activity anomaly",
        "source": "VSA Server",
        "severity": "Low",
        "risk": 15,
        "stage": 1
    },
    {
        "name": "Suspicious command execution",
        "source": "VSA Server",
        "severity": "Medium",
        "risk": 15,
        "stage": 2
    },
    {
        "name": "Unexpected software deployment",
        "source": "Client B (PC-07)",
        "severity": "Medium",
        "risk": 20,
        "stage": 3
    },
    {
        "name": "Multiple endpoints contacted",
        "source": "VSA Server",
        "severity": "High",
        "risk": 15,
        "stage": 4
    },
    {
        "name": "Mass file modification detected",
        "source": "Client C (PC-12)",
        "severity": "High",
        "risk": 25,
        "stage": 5
    }
]


def get_simulation_events():
    """Return a copy of the safe simulation events."""
    return [event.copy() for event in SIMULATION_EVENTS]