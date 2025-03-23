import os
import json
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum

class AlertSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class Alert:
    def __init__(self, message: str, severity: AlertSeverity, timestamp: datetime = None):
        self.message = message
        self.severity = severity
        self.timestamp = timestamp or datetime.now()

    def to_dict(self) -> Dict:
        return {
            "message": self.message,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Alert':
        return cls(
            message=data["message"],
            severity=AlertSeverity(data["severity"]),
            timestamp=datetime.fromisoformat(data["timestamp"])
        )

class AlertManager:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.alerts: List[Alert] = []
        self._load_alerts()

    def _load_alerts(self):
        """Load existing alerts from the log file."""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    content = f.read().strip()
                    if content:  # Only try to parse if file is not empty
                        try:
                            data = json.loads(content)
                            if isinstance(data, list):
                                self.alerts = [Alert.from_dict(alert_data) for alert_data in data]
                            else:
                                self.alerts = []
                        except json.JSONDecodeError:
                            # If JSON parsing fails, start with empty alerts
                            self.alerts = []
                    else:
                        self.alerts = []
        except Exception as e:
            print(f"Error loading alerts: {str(e)}")
            self.alerts = []

    def _save_alerts(self):
        """Save alerts to the log file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            
            # Save alerts as JSON array
            with open(self.log_file, 'w') as f:
                json.dump([alert.to_dict() for alert in self.alerts], f, indent=2)
        except Exception as e:
            print(f"Error saving alerts: {str(e)}")

    def add_alert(self, message: str, severity: AlertSeverity = AlertSeverity.INFO):
        """Add a new alert."""
        try:
            alert = Alert(message, severity)
            self.alerts.append(alert)
            self._save_alerts()
        except Exception as e:
            print(f"Error adding alert: {str(e)}")

    def get_alerts(self, severity: Optional[AlertSeverity] = None) -> List[Alert]:
        """Get all alerts, optionally filtered by severity."""
        if severity:
            return [alert for alert in self.alerts if alert.severity == severity]
        return self.alerts

    def get_recent_alerts(self, count: int = 10) -> List[Alert]:
        """Get the most recent alerts."""
        return sorted(self.alerts, key=lambda x: x.timestamp, reverse=True)[:count]

    def clear_alerts(self):
        """Clear all alerts."""
        self.alerts = []
        self._save_alerts()

    def get_alert_count(self, severity: Optional[AlertSeverity] = None) -> int:
        """Get the count of alerts, optionally filtered by severity."""
        if severity:
            return len([alert for alert in self.alerts if alert.severity == severity])
        return len(self.alerts)

    def get_critical_alerts(self) -> List[Alert]:
        """Get all critical alerts."""
        return self.get_alerts(AlertSeverity.CRITICAL)

    def get_warnings(self) -> List[Alert]:
        """Get all warning alerts."""
        return self.get_alerts(AlertSeverity.WARNING)

    def get_errors(self) -> List[Alert]:
        """Get all error alerts."""
        return self.get_alerts(AlertSeverity.ERROR)

    def get_info_alerts(self) -> List[Alert]:
        """Get all info alerts."""
        return self.get_alerts(AlertSeverity.INFO) 