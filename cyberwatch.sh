#!/bin/bash

# CyberWatch - Advanced Server Monitoring & Security Suite
# A comprehensive monitoring solution with Signal alerts, DDoS detection, and more
# Version: 2.0.0
#
# Copyright (c) 2025 Hidden Protocol Systems
# Author: Hidden Protocol Systems (HiddenProtocol)
# Website: https://hiddenprotocol.com
# License: MIT
#
# This software is provided by Hidden Protocol Systems "as is" without warranties
# of any kind. By using this software you agree to the terms of the license.
#
# Credits:
# - Designed and engineered by Hidden Protocol Systems
# - Includes integrations with: Fail2ban, UFW/iptables, Prometheus client, Flask
# - Special thanks to the open-source community

set -e

# Colors and styling
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ASCII Art
show_banner() {
    clear
    echo -e "${CYAN}CyberWatch - Advanced Server Monitoring & Security Suite${NC}"
    echo -e "${WHITE}Created by Hidden Protocol Systems • https://hiddenprotocol.com${NC}"
    echo -e "${WHITE}Welcome to CyberWatch - Your server's guardian angel!${NC}"
    echo
}

# Create Signal alert script
create_signal_alert_script() {
    print_status "Creating Signal alert script..."
    
    cat > "$ALERT_SCRIPT" << 'EOF'
#!/usr/bin/env python3
import json, requests, logging
from datetime import datetime
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_cfg():
    try:
        with open('/opt/cyberwatch/signal_config.json','r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"signal_api_url": "http://localhost:8080", "signal_number": None, "recipients": []}

def send(alert_type, message):
    cfg = load_cfg()
    if not cfg.get('recipients') or not cfg.get('signal_api_url'):
        logger.warning('Signal not configured')
        return False
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    hostname = open('/etc/hostname').read().strip()
    body = f"🚨 {alert_type} ALERT 🚨\nServer: {hostname}\nTime: {ts}\nMessage: {message}"
    ok = True
    for r in cfg['recipients']:
        payload = {"message": body, "number": cfg.get("signal_number"), "recipients": [r]}
        try:
            resp = requests.post(f"{cfg['signal_api_url']}/v2/send", json=payload, timeout=10)
            if resp.status_code != 201:
                ok = False
        except Exception:
            ok = False
    return ok

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('Usage: send_alert.py <TYPE> <MESSAGE>')
        raise SystemExit(1)
    send(sys.argv[1], sys.argv[2])
EOF

    chown "$SERVICE_USER:$SERVICE_USER" "$ALERT_SCRIPT" || true
    chmod +x "$ALERT_SCRIPT"
}

# Create monitoring app
create_monitoring_app() {
    print_status "Creating monitoring application..."
    
    cat > "$INSTALL_DIR/monitor.py" << 'EOF'
#!/usr/bin/env python3
import os, json, time, logging, psutil, requests, subprocess, threading
from datetime import datetime
from flask import Flask, jsonify, request
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('/var/log/cyberwatch.log'), logging.StreamHandler()])
logger = logging.getLogger(__name__)

cpu_usage = Gauge('system_cpu_usage_percent', 'CPU usage percentage')
memory_usage = Gauge('system_memory_usage_percent', 'Memory usage percentage')
disk_usage = Gauge('system_disk_usage_percent', 'Disk usage percentage')
network_bytes_sent = Counter('system_network_bytes_sent_total', 'Total network bytes sent')
network_bytes_recv = Counter('system_network_bytes_recv_total', 'Total network bytes received')
system_uptime = Gauge('system_uptime_seconds', 'System uptime in seconds')
ssh_logins = Counter('system_ssh_logins_total', 'Total SSH logins')
fail2ban_events = Counter('system_fail2ban_events_total', 'Total fail2ban events')

app = Flask(__name__)

class Monitor:
    def __init__(self):
        self.config = self.load_config()
        self.alert_script = '/opt/cyberwatch/send_alert.py'
        self.ssh_log = '/var/log/auth.log'
        self.f2b_log = '/var/log/fail2ban.log'
        self.cpu_high_start = None
        self.network_spike_start = None
        self.last_net = None
        threading.Thread(target=self.monitor_ssh, daemon=True).start()
        threading.Thread(target=self.monitor_f2b, daemon=True).start()
        threading.Thread(target=self.monitor_updates, daemon=True).start()

    def load_config(self):
        try:
            with open('/opt/cyberwatch/config.json','r') as f:
                return json.load(f)
        except FileNotFoundError:
            return json.loads('''$DEFAULT_CONFIG''')

    def send_alert(self, t, m):
        try:
            if not self.config.get('signal_config',{}).get('enabled', False):
                return
            subprocess.run(['python3', self.alert_script, t, m], check=False, timeout=10)
        except Exception as e:
            logger.error(f'Signal alert error: {e}')

    def monitor_ssh(self):
        if not os.path.exists(self.ssh_log):
            return
        pos = 0
        while True:
            try:
                with open(self.ssh_log,'r') as f:
                    f.seek(pos)
                    for line in f.readlines():
                        if 'sshd' in line and 'Accepted' in line:
                            parts = line.split()
                            if len(parts) >= 11:
                                user = parts[8]; ip = parts[10]
                                ssh_logins.inc()
                                self.send_alert('SSH_LOGIN', f'SSH login: {user} from {ip}')
                    pos = f.tell()
                time.sleep(5)
            except Exception as e:
                logger.error(f'SSH monitor error: {e}'); time.sleep(30)

    def monitor_f2b(self):
        if not os.path.exists(self.f2b_log):
            return
        pos = 0
        while True:
            try:
                with open(self.f2b_log,'r') as f:
                    f.seek(pos)
                    for line in f.readlines():
                        if ' Ban ' in line or 'Ban ' in line:
                            parts = line.split(); ip = parts[5] if len(parts)>=6 else 'unknown'
                            svc = parts[3] if len(parts)>=4 else 'unknown'
                            fail2ban_events.inc(); self.send_alert('FAIL2BAN', f'IP {ip} banned for {svc}')
                        elif 'Unban' in line:
                            parts = line.split(); ip = parts[5] if len(parts)>=6 else 'unknown'
                            svc = parts[3] if len(parts)>=4 else 'unknown'
                            self.send_alert('FAIL2BAN', f'IP {ip} unbanned for {svc}')
                        elif 'Found' in line and 'failures' in line:
                            parts = line.split(); ip = parts[7].rstrip(',') if len(parts)>=8 else 'unknown'
                            svc = parts[2] if len(parts)>=3 else 'unknown'
                            self.send_alert('FAIL2BAN', f'Multiple failures from {ip} for {svc}')
                    pos = f.tell()
                time.sleep(5)
            except Exception as e:
                logger.error(f'fail2ban monitor error: {e}'); time.sleep(30)

    def monitor_updates(self):
        last = 0
        interval = self.config.get('update_check_interval', 3600)
        while True:
            try:
                now = time.time()
                if now - last >= interval:
                    self.check_updates()
                    last = now
                time.sleep(300)
            except Exception as e:
                logger.error(f'update monitor error: {e}'); time.sleep(300)

    def check_updates(self):
        try:
            if os.path.exists('/etc/os-release'):
                data = open('/etc/os-release').read().lower()
                if 'ubuntu' in data or 'debian' in data:
                    os.system('apt-get update -qq')
                    out = os.popen('apt list --upgradable 2>/dev/null').read()
                    up = [l for l in out.split('\n') if 'upgradable' in l]
                    sec = [l for l in up if 'security' in l.lower() or 'ubuntu' in l.lower()]
                    if up:
                        self.send_alert('UPDATES', f'System updates: {len(up)} total, {len(sec)} security')
                else:
                    cmd = 'dnf check-update 2>/dev/null' if os.path.exists('/usr/bin/dnf') else 'yum check-update 2>/dev/null'
                    out = os.popen(cmd).read()
                    lines = [l for l in out.split('\n') if l.strip() and not l.startswith('Last metadata')]
                    if lines:
                        sec = [l for l in lines if 'security' in l.lower()]
                        self.send_alert('UPDATES', f'System updates: {len(lines)} total, {len(sec)} security')
        except Exception as e:
            logger.error(f'check_updates error: {e}')

    def get_metrics(self):
        cpu = psutil.cpu_percent(interval=1); cpu_usage.set(cpu)
        mem = psutil.virtual_memory(); memory_usage.set(mem.percent)
        disk = psutil.disk_usage('/'); disk_usage.set(disk.percent)
        net = psutil.net_io_counters()
        network_bytes_sent.inc(net.bytes_sent); network_bytes_recv.inc(net.bytes_recv)
        uptime = time.time() - psutil.boot_time(); system_uptime.set(uptime)
        # CPU sustained high
        thr = self.config.get('alert_thresholds',{}).get('cpu',90)
        dur = self.config.get('alert_thresholds',{}).get('cpu_duration',300)
        if cpu > thr:
            self.cpu_high_start = self.cpu_high_start or time.time()
            if time.time() - self.cpu_high_start > dur:
                self.send_alert('CPU', f'High CPU {cpu:.1f}% for {dur}s'); self.cpu_high_start = None
        else:
            self.cpu_high_start = None
        # Disk
        if disk.percent > self.config.get('alert_thresholds',{}).get('disk',90):
            self.send_alert('STORAGE', f'Disk space low: {disk.percent:.1f}% on /')
        # Network spike
        if self.last_net:
            dt = time.time() - self.last_net['t']
            bps = (net.bytes_sent - self.last_net['s'] + net.bytes_recv - self.last_net['r']) / max(dt,1)
            n_thr = self.config.get('alert_thresholds',{}).get('network_spike', 100*1024*1024)
            n_dur = self.config.get('alert_thresholds',{}).get('network_duration', 60)
            if bps > n_thr:
                self.network_spike_start = self.network_spike_start or time.time()
                if time.time() - self.network_spike_start > n_dur:
                    self.send_alert('NETWORK', f'Network spike: {bps/1024/1024:.1f}MB/s for {n_dur}s')
                    self.network_spike_start = None
            else:
                self.network_spike_start = None
        self.last_net = {'t': time.time(), 's': net.bytes_sent, 'r': net.bytes_recv}
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu': {'usage_percent': cpu, 'count': psutil.cpu_count()},
            'memory': {'usage_percent': mem.percent, 'total': mem.total},
            'disk': {'usage_percent': disk.percent, 'total': disk.total},
            'network': {'bytes_sent': net.bytes_sent, 'bytes_recv': net.bytes_recv},
            'uptime': uptime,
        }

monitor = Monitor()

@app.route('/health')
def health():
    return jsonify({'status':'healthy','timestamp': datetime.now().isoformat()})

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/api/status')
def status():
    m = monitor.get_metrics()
    return jsonify({'status':'ok','metrics': m, 'alerts': []})

@app.route('/api/config', methods=['GET','POST'])
def config():
    if request.method == 'GET':
        return jsonify(monitor.config)
    data = request.get_json() or {}
    monitor.config.update(data)
    with open('/opt/cyberwatch/config.json','w') as f:
        json.dump(monitor.config, f, indent=2)
    return jsonify({'status':'success'})

if __name__ == '__main__':
    port = monitor.config.get('api_port', 8080)
    logger.info(f'Starting CyberWatch on port {port}')
    app.run(host='0.0.0.0', port=port, debug=False)
EOF

    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/monitor.py" || true
    chmod +x "$INSTALL_DIR/monitor.py"
}

# Create config file
create_config_file() {
    print_status "Creating configuration file..."
    echo "$DEFAULT_CONFIG" > "$CONFIG_FILE"
    chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE" || true
    chmod 644 "$CONFIG_FILE"
}

# Create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=CyberWatch Monitoring Service (Hidden Protocol Systems)
Documentation=https://hiddenprotocol.com
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/monitor.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# Log rotation
setup_log_rotation() {
    print_status "Setting up log rotation..."
    cat > "/etc/logrotate.d/cyberwatch" << EOF
/var/log/cyberwatch.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF
}

# Fail2ban basic setup
setup_fail2ban() {
    print_status "Ensuring Fail2ban is enabled for SSH..."
    mkdir -p /etc/fail2ban/jail.d
    cat > "/etc/fail2ban/jail.d/ssh.local" << 'EOF'
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
    systemctl enable fail2ban || true
    systemctl restart fail2ban || true
}

# Install global CLI command
install_cli_command() {
    print_status "Installing global 'cyberwatch' command..."
    # Place a managed copy of this script into the install dir for stable path
    local SCRIPT_SRC
    if [ -n "${BASH_SOURCE[0]}" ]; then
        SCRIPT_SRC="${BASH_SOURCE[0]}"
    else
        SCRIPT_SRC="$0"
    fi
    # Resolve symlink if any
    if command -v readlink >/dev/null 2>&1; then
        local RL
        RL=$(readlink -f "$SCRIPT_SRC" 2>/dev/null || true)
        if [ -n "$RL" ]; then SCRIPT_SRC="$RL"; fi
    fi
    if [ -r "$SCRIPT_SRC" ]; then
        cp "$SCRIPT_SRC" "$INSTALL_DIR/cyberwatch.sh"
    else
        print_warning "Could not determine script path; expecting script already at $INSTALL_DIR/cyberwatch.sh"
    fi
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/cyberwatch.sh" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/cyberwatch.sh" 2>/dev/null || true
    # Create system-wide launcher
    cat > /usr/local/bin/cyberwatch << 'EOF'
#!/bin/bash
exec sudo /opt/cyberwatch/cyberwatch.sh "$@"
EOF
    chmod +x /usr/local/bin/cyberwatch
    print_success "Command installed: cyberwatch"
}

# Error handling
handle_error() {
    local exit_code=$?
    local line_number=$1
    echo -e "${RED}[ERROR]${NC} Script failed at line $line_number with exit code $exit_code"
    echo -e "${YELLOW}[INFO]${NC} Please check the logs and try again"
    exit $exit_code
}

trap 'handle_error $LINENO' ERR

# Print functions
print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_menu() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    CyberWatch Main Menu                     ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║  ${WHITE}1)${NC} 🚀 Install CyberWatch Monitoring System          ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}2)${NC} 📱 Setup Signal Messenger Alerts                ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}3)${NC} 🛡️  Test DDoS Detection                         ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}4)${NC} 🔒 Test Fail2ban Security                       ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}5)${NC} 🔄 Check System Updates                         ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}6)${NC} 📊 View System Status                          ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}7)${NC} ⚙️  Configure Settings                          ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}8)${NC} 📋 View Logs                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}9)${NC} 🔐 Advanced Security Features                 ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}10)${NC} 🗑️  Uninstall CyberWatch                       ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${WHITE}0)${NC} 🚪 Exit                                        ${CYAN}║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Configuration
INSTALL_DIR="/opt/cyberwatch"
SERVICE_USER="cyberwatch"
SERVICE_NAME="cyberwatch"
CONFIG_FILE="$INSTALL_DIR/config.json"
SIGNAL_CONFIG="$INSTALL_DIR/signal_config.json"
ALERT_SCRIPT="$INSTALL_DIR/send_alert.py"
LOG_FILE="/var/log/cyberwatch.log"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

# Default config values
DEFAULT_CONFIG='{
  "monitoring_interval": 30,
  "alert_thresholds": {
    "cpu": 90,
    "cpu_duration": 300,
    "memory": 85,
    "disk": 90,
    "network_spike": 104857600,
    "network_duration": 60
  },
  "update_check_interval": 3600,
  "ddos_detection": {
    "enabled": true,
    "max_connections_per_ip": 50,
    "max_packets_per_ip": 1000,
    "max_unique_ips": 100,
    "detection_window": 60,
    "min_attack_duration": 30
  },
  "signal_config": {
    "enabled": false,
    "api_url": "http://localhost:8081",
    "number": null,
    "recipients": []
  },
  "api_port": 8080,
  "log_level": "INFO"
}'

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        clear
        echo -e "${RED}"
        cat << 'EOF'
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║                    ⚠️  PERMISSION ERROR  ⚠️                    ║
    ║                                                              ║
    ║    CyberWatch requires root privileges to function          ║
    ║    properly. Please run with sudo:                          ║
    ║                                                              ║
    ║    sudo ./cyberwatch.sh                                     ║
    ║                                                              ║
    ║    This is required for:                                    ║
    ║    • System service management                              ║
    ║    • Network monitoring                                     ║
    ║    • Security configuration                                 ║
    ║    • Log file access                                        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
EOF
        echo -e "${NC}"
        echo -e "${YELLOW}Exiting...${NC}"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VERSION=$(lsb_release -sr)
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    print_status "Detected OS: $OS $VERSION"
}

# Install dependencies
install_dependencies() {
    print_header "Installing System Dependencies"
    
    case $OS in
        ubuntu|debian)
            apt-get update
            # Note: iptables-persistent conflicts with ufw on some Ubuntu releases; omit it
            apt-get install -y python3 python3-pip python3-venv curl wget git jq htop iotop nethogs fail2ban bc net-tools ufw
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip curl wget git jq htop iotop nethogs fail2ban bc net-tools
            else
                yum install -y python3 python3-pip curl wget git jq htop iotop nethogs fail2ban bc net-tools
            fi
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    print_success "Dependencies installed successfully"
}

# Create service user
create_service_user() {
    print_status "Creating CyberWatch service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        usermod -aG adm "$SERVICE_USER" || true
        print_success "Service user created"
    else
        print_warning "Service user already exists"
        usermod -aG adm "$SERVICE_USER" || true
    fi
}

# Create installation directory
create_install_directory() {
    print_status "Creating CyberWatch installation directory..."
    
    mkdir -p "$INSTALL_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    # Ensure application log file exists and is writable by service user
    touch "$LOG_FILE" 2>/dev/null || true
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_FILE" 2>/dev/null || true
    
    print_success "Installation directory created"
}

# Setup Python environment
setup_python_environment() {
    print_status "Setting up Python virtual environment..."
    
    cd "$INSTALL_DIR"
    python3 -m venv venv
    source venv/bin/activate
    
    pip install --upgrade pip
    # Core runtime deps (Signal alerts use HTTP directly; no extra client lib needed)
    pip install psutil requests flask prometheus-client
    
    print_success "Python environment created and dependencies installed"
}

# Main menu function
show_main_menu() {
    while true; do
        show_banner
        print_menu
        echo -e "${WHITE}Select an option (0-10): ${NC}\c"
        read -r choice
        
        case $choice in
            1) install_cyberwatch ;;
            2) setup_signal ;;
            3) test_ddos ;;
            4) test_fail2ban ;;
            5) check_updates ;;
            6) view_status ;;
            7) configure_settings ;;
            8) view_logs ;;
            9) advanced_security ;;
            10) uninstall_cyberwatch ;;
            0) exit_cyberwatch ;;
            *) print_error "Invalid option. Please select 0-10." ;;
        esac
        
        echo
        echo -e "${YELLOW}Press Enter to continue...${NC}"
        read -r
    done
}

# Install CyberWatch
install_cyberwatch() {
    print_header "Installing CyberWatch Monitoring System"
    
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "CyberWatch appears to be already installed"
        echo -e "${YELLOW}Do you want to reinstall? (y/N): ${NC}\c"
        read -r reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            return
        fi
    fi
    
    detect_os
    install_dependencies
    create_service_user
    create_install_directory
    setup_python_environment
    create_signal_alert_script
    create_monitoring_app
    create_config_file
    create_systemd_service
    setup_log_rotation
    setup_fail2ban
    install_cli_command
    
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "CyberWatch service is running and enabled at boot"
        print_status "You can reopen this console anytime by running: cyberwatch"
    else
        print_error "CyberWatch service failed to start"
        systemctl status "$SERVICE_NAME" || true
    fi
}

# Setup Signal
setup_signal() {
    print_header "Setting up Signal Messenger Alerts"
    
    if [ ! -d "$INSTALL_DIR" ]; then
        print_error "CyberWatch is not installed. Please install first (option 1)"
        return
    fi
    
    echo -e "${WHITE}Enter your Signal phone number (e.g., +15551234567): ${NC}\c"
    read -r SIGNAL_NUMBER
    if [ -z "$SIGNAL_NUMBER" ]; then
        print_error "Signal number is required"
        return
    fi
    echo -e "${WHITE}Enter recipient numbers (comma-separated): ${NC}\c"
    read -r RECIPIENTS_CSV
    
    IFS=',' read -r -a RECIPIENTS_ARR <<< "$RECIPIENTS_CSV"
    RECIPIENTS_JSON=$(printf '"%s",' "${RECIPIENTS_ARR[@]}")
    RECIPIENTS_JSON="[${RECIPIENTS_JSON%,}]"
    
    cat > "$SIGNAL_CONFIG" << EOF
{
  "signal_api_url": "http://localhost:8080",
  "signal_number": "$SIGNAL_NUMBER",
  "recipients": $RECIPIENTS_JSON
}
EOF
    chown "$SERVICE_USER:$SERVICE_USER" "$SIGNAL_CONFIG" || true
    chmod 644 "$SIGNAL_CONFIG"
    
    # Enable in main config
    python3 - << PY
import json
cfg_path = "$CONFIG_FILE"
with open(cfg_path) as f:
    cfg = json.load(f)
cfg.setdefault('signal_config',{})['enabled'] = True
with open(cfg_path,'w') as f:
    json.dump(cfg, f, indent=2)
PY
    
    systemctl restart "$SERVICE_NAME"
    sleep 2
    print_success "Signal configured and service restarted"
    
    # Send test alert
    $INSTALL_DIR/venv/bin/python "$ALERT_SCRIPT" TEST "Test alert from CyberWatch"
}

# Test DDoS
test_ddos() {
    print_header "DDoS Detection Overview"
    echo "Detection is passive and pattern-based (connections, unique IPs, spikes)."
    echo "Current connections: $(netstat -tn | grep -c ESTABLISHED)"
    echo "Top remote IPs (last 100):"
    netstat -tn | awk 'NR>2 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
    echo
    print_status "No active synthetic flood generated to avoid impacting production."
}

# Test Fail2ban
test_fail2ban() {
    print_header "Fail2ban Status"
    systemctl is-active --quiet fail2ban && print_success "Fail2ban is active" || print_warning "Fail2ban not active"
    echo
    fail2ban-client status 2>/dev/null || echo "fail2ban-client not available"
}

# Check updates
check_updates() {
    print_header "Checking System Updates"
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        apt-get update -qq
        COUNT=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
        echo "Upgradable packages: $COUNT"
        if [ "$COUNT" -gt 0 ]; then
            apt list --upgradable 2>/dev/null | head -20
        fi
    else
        if command -v dnf &>/dev/null; then
            dnf -q check-update || true
        else
            yum -q check-update || true
        fi
    fi
}

# View status
view_status() {
    print_header "CyberWatch System Status"
    
    echo -e "${WHITE}Service Status:${NC}"
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_success "CyberWatch service is running"
    else
        print_warning "CyberWatch service is not running"
    fi
    
    echo
    echo -e "${WHITE}System Information:${NC}"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo "Load: $(uptime | awk '{print $10 $11 $12}')"
    echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
    echo "Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
    
    echo
    echo -e "${WHITE}Network Connections:${NC}"
    echo "Active connections: $(netstat -tn | grep -c ESTABLISHED)"
    
    if [ -f "$CONFIG_FILE" ]; then
        echo
        echo -e "${WHITE}Configuration:${NC}"
        echo "Config file: $CONFIG_FILE"
        echo "Log file: $LOG_FILE"
        echo "Installation: $INSTALL_DIR"
    fi
}

# Configure settings
configure_settings() {
    print_header "Configure CyberWatch Settings"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "Configuration file not found. Please install CyberWatch first."
        return
    fi
    
    echo -e "${WHITE}Current configuration:${NC}"
    cat "$CONFIG_FILE" | jq . 2>/dev/null || cat "$CONFIG_FILE"
    
    echo
    echo -e "${YELLOW}Configuration options:${NC}"
    echo "1) Edit configuration file"
    echo "2) Restart service"
    echo "3) View Signal configuration"
    echo "4) Test Signal alerts"
    echo "0) Back to main menu"
    
    echo -e "${WHITE}Select option: ${NC}\c"
    read -r config_choice
    
    case $config_choice in
        1) nano "$CONFIG_FILE" ;;
        2) systemctl restart "$SERVICE_NAME" ;;
        3) cat "$SIGNAL_CONFIG" 2>/dev/null || echo "Signal config not found" ;;
        4) curl -X POST http://localhost:8080/api/signal/test -H "Content-Type: application/json" -d '{"message": "Test alert from CyberWatch"}' ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

# View logs
view_logs() {
    print_header "CyberWatch Logs"
    
    echo -e "${WHITE}Select log type:${NC}"
    echo "1) Service logs (journalctl)"
    echo "2) Application logs"
    echo "3) Fail2ban logs"
    echo "4) System logs"
    echo "0) Back to main menu"
    
    echo -e "${WHITE}Select option: ${NC}\c"
    read -r log_choice
    
    case $log_choice in
        1) journalctl -u "$SERVICE_NAME" -f ;;
        2) tail -f "$LOG_FILE" 2>/dev/null || echo "Log file not found" ;;
        3) tail -f /var/log/fail2ban.log 2>/dev/null || echo "Fail2ban log not found" ;;
        4) tail -f /var/log/syslog 2>/dev/null || tail -f /var/log/messages 2>/dev/null || echo "System log not found" ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

# Advanced Security Features
advanced_security() {
    print_header "Advanced Security Features"
    
    echo -e "${WHITE}Select security feature:${NC}"
    echo "1) 🔥 Configure Firewall (UFW/iptables)"
    echo "2) 🛡️  Harden SSH Configuration"
    echo "3) 🔒 Set up Intrusion Detection (AIDE)"
    echo "4) 🚨 Configure Security Alerts"
    echo "5) 🔐 Enable Two-Factor Authentication"
    echo "6) 🛠️  System Security Audit"
    echo "7) 🚫 Block Suspicious IPs"
    echo "8) 📊 Security Status Report"
    echo "0) Back to main menu"
    
    echo -e "${WHITE}Select option: ${NC}\c"
    read -r security_choice
    
    case $security_choice in
        1) configure_firewall ;;
        2) harden_ssh ;;
        3) setup_aide ;;
        4) configure_security_alerts ;;
        5) setup_2fa ;;
        6) security_audit ;;
        7) block_suspicious_ips ;;
        8) security_report ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

# Configure Firewall
configure_firewall() {
    print_header "Configuring Firewall Security"
    
    echo -e "${WHITE}Firewall Configuration Options:${NC}"
    echo "1) Enable UFW (Ubuntu/Debian)"
    echo "2) Configure iptables rules"
    echo "3) Block common attack ports"
    echo "4) Allow only SSH and HTTP/HTTPS"
    echo "5) View current firewall status"
    echo "0) Back"
    
    echo -e "${WHITE}Select option: ${NC}\c"
    read -r firewall_choice
    
    case $firewall_choice in
        1)
            print_status "Enabling UFW firewall..."
            ufw --force enable
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw allow 80/tcp
            ufw allow 443/tcp
            print_success "UFW firewall configured"
            ;;
        2)
            print_status "Configuring iptables rules..."
            # Basic iptables rules
            iptables -F
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            iptables -A INPUT -p tcp --dport 80 -j ACCEPT
            iptables -A INPUT -p tcp --dport 443 -j ACCEPT
            iptables-save > /etc/iptables/rules.v4
            print_success "iptables rules configured"
            ;;
        3)
            print_status "Blocking common attack ports..."
            # Block common attack ports
            iptables -A INPUT -p tcp --dport 23 -j DROP    # Telnet
            iptables -A INPUT -p tcp --dport 21 -j DROP    # FTP
            iptables -A INPUT -p tcp --dport 135 -j DROP   # RPC
            iptables -A INPUT -p tcp --dport 139 -j DROP   # NetBIOS
            iptables -A INPUT -p tcp --dport 445 -j DROP   # SMB
            print_success "Attack ports blocked"
            ;;
        4)
            print_status "Configuring restrictive firewall..."
            ufw --force reset
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw --force enable
            print_success "Restrictive firewall configured"
            ;;
        5)
            print_status "Current firewall status:"
            ufw status verbose
            ;;
        0) return ;;
        *) print_error "Invalid option" ;;
    esac
}

# Harden SSH Configuration
harden_ssh() {
    print_header "Hardening SSH Configuration"
    
    print_status "Backing up SSH configuration..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
    
    print_status "Applying SSH security hardening..."
    
    # Disable root login
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Disable password authentication (key-based only)
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Disable empty passwords
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    
    # Change default port (optional)
    echo -e "${YELLOW}Do you want to change SSH port from 22? (y/N): ${NC}\c"
    read -r change_port
    if [[ "$change_port" =~ ^[Yy]$ ]]; then
        echo -e "${WHITE}Enter new SSH port (1024-65535): ${NC}\c"
        read -r new_port
        sed -i "s/#Port 22/Port $new_port/" /etc/ssh/sshd_config
        sed -i "s/Port 22/Port $new_port/" /etc/ssh/sshd_config
        print_warning "Remember to update firewall rules for new port $new_port"
    fi
    
    # Restart SSH service
    systemctl restart sshd
    
    print_success "SSH configuration hardened"
    print_warning "Test SSH connection before closing this session!"
}

# Setup AIDE (Advanced Intrusion Detection Environment)
setup_aide() {
    print_header "Setting up AIDE Intrusion Detection"
    
    # Install AIDE
    case $OS in
        ubuntu|debian)
            apt-get install -y aide aide-common
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y aide
            else
                yum install -y aide
            fi
            ;;
    esac
    
    print_status "Initializing AIDE database..."
    aideinit
    
    print_status "Moving database to secure location..."
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    print_status "Setting up daily AIDE checks..."
    cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/bin/aide --check
if [ $? -ne 0 ]; then
    echo "AIDE detected changes" | mail -s "AIDE Alert" root
fi
EOF
    chmod +x /etc/cron.daily/aide
    
    print_success "AIDE intrusion detection configured"
}

# Configure Security Alerts
configure_security_alerts() {
    print_header "Configuring Advanced Security Alerts"
    
    # Create security monitoring script
    cat > "$INSTALL_DIR/security_monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
Advanced Security Monitoring
Monitors system security events and sends alerts
"""

import os
import sys
import json
import time
import logging
import subprocess
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityMonitor:
    def __init__(self):
        self.config = self.load_config()
        
    def load_config(self):
        try:
            with open('/opt/cyberwatch/config.json', 'r') as f:
                return json.load(f)
        except:
            return {"security_alerts": {"enabled": True}}
    
    def check_suspicious_activity(self):
        """Check for suspicious system activity"""
        alerts = []
        
        # Check for unusual login patterns
        recent_logins = subprocess.run(['last', '-n', '20'], capture_output=True, text=True)
        if recent_logins.returncode == 0:
            lines = recent_logins.stdout.split('\n')
            for line in lines:
                if 'pts' in line and 'still logged in' not in line:
                    # Check for unusual login times or patterns
                    if any(time in line for time in ['00:', '01:', '02:', '03:', '04:', '05:']):
                        alerts.append(f"Unusual login time detected: {line.strip()}")
        
        # Check for failed login attempts
        failed_logins = subprocess.run(['grep', 'Failed password', '/var/log/auth.log'], capture_output=True, text=True)
        if failed_logins.returncode == 0:
            failed_count = len(failed_logins.stdout.split('\n'))
            if failed_count > 10:
                alerts.append(f"High number of failed login attempts: {failed_count}")
        
        # Check for privilege escalation attempts
        sudo_attempts = subprocess.run(['grep', 'sudo', '/var/log/auth.log'], capture_output=True, text=True)
        if sudo_attempts.returncode == 0:
            sudo_count = len(sudo_attempts.stdout.split('\n'))
            if sudo_count > 5:
                alerts.append(f"Multiple sudo attempts detected: {sudo_count}")
        
        return alerts
    
    def check_file_integrity(self):
        """Check for file integrity issues"""
        alerts = []
        
        # Check for recently modified system files
        critical_files = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers']
        for file_path in critical_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                mod_time = datetime.fromtimestamp(stat.st_mtime)
                if (datetime.now() - mod_time).days < 1:
                    alerts.append(f"Critical system file recently modified: {file_path}")
        
        return alerts
    
    def send_security_alert(self, alerts):
        """Send security alerts"""
        if alerts:
            message = "Security Alert: " + "; ".join(alerts)
            subprocess.run(['python3', '/opt/cyberwatch/send_alert.py', 'SECURITY', message])
    
    def run_security_checks(self):
        """Run all security checks"""
        alerts = []
        alerts.extend(self.check_suspicious_activity())
        alerts.extend(self.check_file_integrity())
        
        if alerts:
            self.send_security_alert(alerts)
            logger.warning(f"Security alerts triggered: {len(alerts)}")

if __name__ == '__main__':
    monitor = SecurityMonitor()
    monitor.run_security_checks()
EOF
    
    chmod +x "$INSTALL_DIR/security_monitor.py"
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/15 * * * * /opt/cyberwatch/venv/bin/python3 /opt/cyberwatch/security_monitor.py") | crontab -
    
    print_success "Advanced security alerts configured"
}

# Setup Two-Factor Authentication
setup_2fa() {
    print_header "Setting up Two-Factor Authentication"
    
    print_status "Installing Google Authenticator PAM module..."
    case $OS in
        ubuntu|debian)
            apt-get install -y libpam-google-authenticator
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y google-authenticator
            else
                yum install -y google-authenticator
            fi
            ;;
    esac
    
    print_status "Configuring PAM for 2FA..."
    echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
    
    print_status "Updating SSH configuration for 2FA..."
    echo "ChallengeResponseAuthentication yes" >> /etc/ssh/sshd_config
    echo "AuthenticationMethods publickey,password publickey,keyboard-interactive" >> /etc/ssh/sshd_config
    
    systemctl restart sshd
    
    print_success "Two-factor authentication configured"
    print_warning "Run 'google-authenticator' for each user to set up their 2FA"
}

# Security Audit
security_audit() {
    print_header "Running Security Audit"
    
    print_status "Checking system security status..."
    
    # Check for open ports
    print_status "Open network ports:"
    netstat -tlnp | grep LISTEN
    
    # Check for SUID files
    print_status "SUID files (potential security risk):"
    find / -perm -4000 -type f 2>/dev/null | head -10
    
    # Check for world-writable files
    print_status "World-writable files:"
    find / -perm -002 -type f 2>/dev/null | head -10
    
    # Check for empty password users
    print_status "Users with empty passwords:"
    awk -F: '($2 == "") {print $1}' /etc/shadow
    
    # Check for recent security updates
    print_status "Security update status:"
    case $OS in
        ubuntu|debian)
            apt list --upgradable | grep -i security
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf check-update | grep -i security
            else
                yum check-update | grep -i security
            fi
            ;;
    esac
    
    print_success "Security audit completed"
}

# Block Suspicious IPs
block_suspicious_ips() {
    print_header "Blocking Suspicious IPs"
    
    print_status "Analyzing logs for suspicious IPs..."
    
    # Extract IPs with multiple failed login attempts
    suspicious_ips=$(grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head -10)
    
    if [ -n "$suspicious_ips" ]; then
        echo -e "${WHITE}Suspicious IPs found:${NC}"
        echo "$suspicious_ips"
        
        echo -e "${YELLOW}Do you want to block these IPs? (y/N): ${NC}\c"
        read -r block_ips
        
        if [[ "$block_ips" =~ ^[Yy]$ ]]; then
            echo "$suspicious_ips" | awk '{print $2}' | while read ip; do
                if [ -n "$ip" ] && [ "$ip" != "from" ]; then
                    iptables -A INPUT -s "$ip" -j DROP
                    print_status "Blocked IP: $ip"
                fi
            done
            print_success "Suspicious IPs blocked"
        fi
    else
        print_status "No suspicious IPs found"
    fi
}

# Security Status Report
security_report() {
    print_header "Security Status Report"
    
    echo -e "${WHITE}=== Security Status Report ===${NC}"
    echo "Generated: $(date)"
    echo
    
    # Firewall status
    echo -e "${BLUE}Firewall Status:${NC}"
    ufw status 2>/dev/null || iptables -L 2>/dev/null || echo "No firewall configured"
    echo
    
    # SSH status
    echo -e "${BLUE}SSH Configuration:${NC}"
    grep -E "^(PermitRootLogin|PasswordAuthentication|Port)" /etc/ssh/sshd_config 2>/dev/null || echo "SSH config not found"
    echo
    
    # Fail2ban status
    echo -e "${BLUE}Fail2ban Status:${NC}"
    systemctl is-active fail2ban 2>/dev/null && fail2ban-client status || echo "Fail2ban not active"
    echo
    
    # Recent security events
    echo -e "${BLUE}Recent Security Events:${NC}"
    tail -5 /var/log/auth.log 2>/dev/null || echo "Auth log not accessible"
    echo
    
    # System updates
    echo -e "${BLUE}Security Updates:${NC}"
    case $OS in
        ubuntu|debian)
            apt list --upgradable | grep -c security 2>/dev/null || echo "0"
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf check-update | grep -c security 2>/dev/null || echo "0"
            else
                yum check-update | grep -c security 2>/dev/null || echo "0"
            fi
            ;;
    esac
    echo "security updates available"
    echo
    
    print_success "Security report generated"
}

# Uninstall CyberWatch
uninstall_cyberwatch() {
    print_header "Uninstalling CyberWatch"
    
    echo -e "${RED}WARNING: This will completely remove CyberWatch and all its data!${NC}"
    echo -e "${YELLOW}Are you sure you want to continue? (y/N): ${NC}\c"
    read -r confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        print_status "Stopping and disabling service..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        
        print_status "Removing files..."
        rm -rf "$INSTALL_DIR"
        rm -f "$SERVICE_FILE"
        rm -f "/etc/logrotate.d/cyberwatch"
        
        print_status "Removing service user..."
        userdel "$SERVICE_USER" 2>/dev/null || true
        
        print_success "CyberWatch has been uninstalled"
    else
        print_status "Uninstall cancelled"
    fi
}

# Exit
exit_cyberwatch() {
    print_header "Thank you for using CyberWatch!"
    echo -e "${GREEN}Stay secure! 🛡️${NC}"
    exit 0
}

# Main execution
main() {
    check_root
    show_main_menu
}

# Run main function
main "$@"
