class SecurityMonitor:
    def __init__(self):
        self.suspicious_activities = []
        self.thresholds = {
            'failed_attempts': 5,
            'unusual_time': True,
            'data_size': 10000000  # 10MB
        }
    
    def monitor_activity(self, user, action, data_size=0):
        """Monitor user activities for security threats."""
        warnings = []
        
        # Check for unusual activity patterns
        if self.is_unusual_time():
            warnings.append("Activity at unusual time")
        
        # if data_size > self.th 