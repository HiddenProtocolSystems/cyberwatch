# CyberWatch - Advanced Server Monitoring & Security Suite

Created by Hidden Protocol Systems • https://hiddenprotocol.com

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![OS: Ubuntu/Debian](https://img.shields.io/badge/OS-Ubuntu%2FDebian-blue)

## Table of Contents
- [Features](#features)
- [Quick Installation](#quick-installation)
- [Manual Installation](#manual-installation)
- [Configuration](#configuration)
- [Signal Messenger Setup](#signal-messenger-setup)
- [Usage](#usage)
- [Choose What to Monitor](#choose-what-to-monitor)
- [Uninstall](#uninstall)
- [Security Notes](#security-notes)
- [Credits](#credits)

A comprehensive server monitoring solution that provides real-time system metrics, Signal alerts, DDoS detection, Fail2ban integration, and advanced security monitoring for Linux servers.

## Features

- **Real-time Monitoring**: CPU, memory, disk, and network usage
- **Signal Messenger Alerts**: Critical alerts sent via Signal messenger
- **System Event Monitoring**: 
  - System restart detection
  - SSH login monitoring
  - Fail2ban event monitoring
  - System update notifications
  - DDoS attack detection
- **Advanced Alerting**:
  - Sustained high CPU usage alerts
  - Storage space warnings
  - Network traffic spike detection
  - Available system updates
  - DDoS attack alerts
- **Prometheus Metrics**: Compatible with Prometheus monitoring stack
- **REST API**: JSON API for integration with other tools
- **Systemd Integration**: Runs as a system service
- **Log Rotation**: Automatic log management
- **Easy Installation**: Single-file installer script

## Quick Installation

### Prerequisites

- Linux server (Ubuntu/Debian or CentOS/RHEL)
- Root or sudo access
- Internet connection

### Launch

```bash
# Download and run the CyberWatch unified script from GitHub
wget https://raw.githubusercontent.com/HiddenProtocolSystems/cyberwatch/main/cyberwatch.sh
chmod +x cyberwatch.sh
sudo ./cyberwatch.sh
```

The interactive menu provides:
- 🚀 One-click installation
- 📱 Signal messenger setup
- 🛡️ DDoS detection testing
- 🔒 Fail2ban security testing
- 🔄 System update checking
- 📊 Real-time status monitoring
- ⚙️ Configuration management
- 📋 Log viewing
- 🗑️ Easy uninstallation

## Manual Installation

If you already have the script locally:

```bash
sudo ./cyberwatch.sh
```

## Configuration

The service is configured via `/opt/cyberwatch/config.json`:

```json
{
  "monitoring_interval": 30,
  "alert_thresholds": {
    "cpu": 90,
    "cpu_duration": 300,
    "memory": 85,
    "disk": 90,
    "network_spike": 104857600,
    "network_duration": 60
  },
  "signal_config": {
    "enabled": false,
    "api_url": "http://localhost:8081",
    "number": null,
    "recipients": []
  },
  "api_port": 8080,
  "log_level": "INFO"
}
```

### Configuration Options

- `monitoring_interval`: How often to collect metrics (seconds)
- `alert_thresholds`: 
  - `cpu`: CPU usage threshold (default: 90%)
  - `cpu_duration`: How long CPU must be high before alert (default: 300s)
  - `memory`: Memory usage threshold (default: 85%)
  - `disk`: Disk usage threshold (default: 90%)
  - `network_spike`: Network traffic spike threshold in bytes/sec (default: 100MB/s)
  - `network_duration`: How long network spike must last before alert (default: 60s)
- `update_check_interval`: How often to check for system updates in seconds (default: 3600 = 1 hour)
- `ddos_detection`: DDoS attack detection configuration
  - `enabled`: Enable DDoS detection (default: true)
  - `max_connections_per_ip`: Max connections per IP in detection window (default: 50)
  - `max_packets_per_ip`: Max packets per IP in detection window (default: 1000)
  - `max_unique_ips`: Max unique IPs in detection window (default: 100)
  - `detection_window`: Detection window in seconds (default: 60)
  - `min_attack_duration`: Minimum attack duration to trigger alert (default: 30s)
- `signal_config`: Signal messenger configuration
  - `enabled`: Enable Signal alerts (default: false)
  - `api_url`: Signal CLI API URL
  - `number`: Your Signal phone number
  - `recipients`: List of recipient phone numbers
- `api_port`: Port for the REST API
- `log_level`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Signal Messenger Setup

To enable Signal alerts, you need to set up Signal CLI and configure your phone number. CyberWatch includes a guided setup inside the menu.

```bash
sudo ./cyberwatch.sh   # then choose: 2) Setup Signal Messenger Alerts
```

### Manual Setup

1. **Install Signal CLI**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install openjdk-11-jre-headless wget
   cd /tmp
   wget https://github.com/AsamK/signal-cli/releases/latest/download/signal-cli-0.11.5.1.tar.gz
   tar -xzf signal-cli-0.11.5.1.tar.gz
   sudo mv signal-cli-0.11.5.1 /opt/signal-cli
   sudo ln -sf /opt/signal-cli/bin/signal-cli /usr/local/bin/signal-cli
   ```

2. **Register your phone number**:
   ```bash
   signal-cli -a +1234567890 register
   # Check your phone for verification code
   signal-cli -a +1234567890 verify <verification_code>
   ```

3. **Configure the service**:
   ```bash
   # Update Signal configuration
   sudo nano /opt/cyberwatch/signal_config.json
   
   # Enable Signal alerts in main config
   sudo nano /opt/cyberwatch/config.json
   ```

4. **Restart the service** (if installed as systemd):
  ```bash
  sudo systemctl restart cyberwatch
  ```

## Usage

### Service Management (systemd)

```bash
# Check service status
sudo systemctl status cyberwatch

# Start/stop/restart service
sudo systemctl start cyberwatch
sudo systemctl stop cyberwatch
sudo systemctl restart cyberwatch

# View logs
sudo journalctl -u cyberwatch -f
```

### API Endpoints

- **Health Check**: `GET http://localhost:8080/health`
- **System Status**: `GET http://localhost:8080/api/status`
- **Prometheus Metrics**: `GET http://localhost:8080/metrics`
- **Configuration**: `GET/POST http://localhost:8080/api/config`

### CLI

All actions are available via the CyberWatch menu in `cyberwatch.sh`.

## Choose What to Monitor

You can enable/disable components via the menu or by editing `/opt/cyberwatch/config.json`:

- CPU alerts: `alert_thresholds.cpu` and `alert_thresholds.cpu_duration`
- Disk alerts: `alert_thresholds.disk`
- Network spike alerts: `alert_thresholds.network_spike`, `alert_thresholds.network_duration`
- Update checks: `update_check_interval` (set to `0` to disable)
- DDoS detection: `ddos_detection.enabled`
- Signal alerts: `signal_config.enabled`

Changes via menu automatically restart the service.

## Uninstall

Use the menu option “Uninstall CyberWatch” or run:

```bash
sudo cyberwatch  # open menu → 10) Uninstall CyberWatch
```

This will stop and disable the service, remove files under `/opt/cyberwatch`, remove the systemd unit, logrotate file, and the global CLI.

## Security Notes

- Runs as a dedicated user `cyberwatch` with least privileges
- UFW/iptables options available via the security menu
- Fail2ban SSH jail enabled by default
- Use 2FA option to harden SSH

## Credits

CyberWatch is created and maintained by Hidden Protocol Systems — `https://hiddenprotocol.com`.
### Example API Usage

```bash
# Get current system status
curl http://localhost:8080/api/status

# Get Prometheus metrics
curl http://localhost:8080/metrics

# Update configuration
curl -X POST http://localhost:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"alert_thresholds": {"cpu": 90}}'

# Test Signal alert
curl -X POST http://localhost:8080/api/signal/test \
  -H "Content-Type: application/json" \
  -d '{"message": "Test alert from CyberWatch"}'
```

## Fail2ban Integration

The system includes comprehensive Fail2ban monitoring and configuration:

### Fail2ban Features

- **Automatic Configuration**: Sets up Fail2ban with optimized settings
- **Multiple Jail Support**: SSH, Apache, Nginx, Postfix, and more
- **Real-time Monitoring**: Tracks ban/unban events
- **Signal Alerts**: Immediate notifications for security events
- **Recidive Protection**: Long-term ban for repeat offenders

### Fail2ban Configuration

The system automatically configures Fail2ban with:

```ini
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
ignoreip = 127.0.0.1/8 ::1

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
bantime = 86400
findtime = 86400
maxretry = 5
```

### Fail2ban Testing

Test Fail2ban functionality with the included test script:

```bash
# Test Fail2ban with failed login attempts
sudo ./test_fail2ban.sh --attempts 3 --duration 20

# Test with custom IP and monitoring
sudo ./test_fail2ban.sh --ip 10.0.0.100 --user admin --monitor

# Check Fail2ban status only
sudo ./test_fail2ban.sh --check-only

# Show help
./test_fail2ban.sh --help
```

### Fail2ban Monitoring Features

- **Ban Detection**: Alerts when IPs are banned
- **Unban Detection**: Alerts when IPs are unbanned
- **Failure Detection**: Alerts on multiple authentication failures
- **Service Integration**: Monitors SSH, web servers, mail servers
- **Recidive Tracking**: Long-term monitoring of repeat offenders

## Monitoring Features

### System Event Monitoring

The service monitors several critical system events:

1. **System Restart Detection**: Automatically detects when the server restarts
2. **SSH Login Monitoring**: Tracks all SSH login attempts with user and IP information
3. **Fail2ban Integration**: Monitors fail2ban events and IP bans
4. **System Update Monitoring**: Checks for available system updates and security patches
5. **DDoS Attack Detection**: Monitors network traffic patterns to detect potential DDoS attacks

### Advanced Alerting

The service provides intelligent alerting for:

1. **Sustained High CPU Usage**: Alerts when CPU usage exceeds threshold for a specified duration
2. **Storage Space Warnings**: Alerts when disk usage exceeds configured threshold
3. **Network Traffic Spikes**: Detects and alerts on unusual network activity patterns
4. **System Updates Available**: Alerts when system updates are available, including security updates
5. **DDoS Attack Detection**: Alerts when potential DDoS attacks are detected based on connection patterns

### Alert Types

- **RESTART**: System has been restarted
- **SSH_LOGIN**: SSH login detected (with user and IP)
- **FAIL2BAN**: IP banned/unbanned by Fail2ban (with IP and service information)
- **CPU**: High CPU usage sustained for too long
- **STORAGE**: Disk space running low
- **NETWORK**: Network traffic spike detected
- **UPDATES**: System updates available (with count of total and security updates)
- **DDOS**: DDoS attack detected (with attack type and source information)

## Monitoring Integration

### Prometheus

Add this to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'server-monitor'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
    scrape_interval: 30s
```

### Grafana Dashboard

Import the following dashboard JSON or create panels for:

- CPU Usage: `system_cpu_usage_percent`
- Memory Usage: `system_memory_usage_percent`
- Disk Usage: `system_disk_usage_percent`
- Network Traffic: `system_network_bytes_sent_total`, `system_network_bytes_recv_total`
- System Uptime: `system_uptime_seconds`

## Alerting

### Webhook Configuration

1. Create a webhook in Slack, Discord, or your preferred service
2. Update the `webhook_url` in the configuration
3. Alerts will be sent when thresholds are exceeded

### Custom Alerting

You can integrate with any monitoring system that supports webhooks or can query the REST API.

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status server-monitor

# Check logs
sudo journalctl -u server-monitor -n 50

# Check configuration
sudo cat /opt/server-monitor/config.json
```

### Permission Issues

```bash
# Fix ownership
sudo chown -R monitor:monitor /opt/server-monitor
sudo chmod +x /opt/server-monitor/monitor.py
```

### Port Already in Use

```bash
# Check what's using port 8080
sudo netstat -tlnp | grep :8080

# Change port in configuration
sudo nano /opt/server-monitor/config.json
sudo systemctl restart server-monitor
```

## Uninstallation

```bash
# Run the uninstall script
sudo /opt/server-monitor/uninstall.sh
```

This will:
- Stop and disable the service
- Remove all files and directories
- Remove the service user
- Clean up systemd configuration

## Security Considerations

- The service runs as a non-privileged user (`monitor`)
- API is bound to localhost by default
- Logs are rotated automatically
- Configuration files have appropriate permissions

## Development

### Project Structure

```
/opt/server-monitor/
├── monitor.py          # Main application
├── config.json         # Configuration
├── dashboard.sh        # CLI dashboard
├── uninstall.sh        # Uninstall script
├── venv/              # Python virtual environment
└── logs/              # Log files
```

### Adding Custom Metrics

Extend the `SystemMonitor` class to add custom metrics:

```python
def get_custom_metrics(self):
    # Your custom monitoring logic here
    return {"custom_metric": value}
```

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Check the logs: `sudo journalctl -u server-monitor -f`
- Verify configuration: `curl http://localhost:8080/api/config`
- Test health: `curl http://localhost:8080/health`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request
