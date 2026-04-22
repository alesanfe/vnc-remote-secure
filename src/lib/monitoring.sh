#!/bin/bash
set -e
set -o pipefail
# ============================================================================
# PROMETHEUS + GRAFANA MONITORING MODULE
# ============================================================================

# Monitoring Configuration
export MONITORING_ENABLED="${MONITORING_ENABLED:-false}"
export PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
export GRAFANA_PORT="${GRAFANA_PORT:-3000}"
export NODE_EXPORTER_PORT="${NODE_EXPORTER_PORT:-9100}"

# Install Node Exporter (for system metrics)
install_node_exporter() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Installing Node Exporter..." "⚙️"
    
    if ! command -v node_exporter &>/dev/null; then
        local arch=$(uname -m)
        case "$arch" in
            x86_64) arch="amd64" ;;
            armv7l) arch="arm" ;;
            aarch64) arch="arm64" ;;
        esac
        
        wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-${arch}.tar.gz -O /tmp/node_exporter.tar.gz
        tar -xzf /tmp/node_exporter.tar.gz -C /tmp
        sudo mv /tmp/node_exporter-1.6.1.linux-${arch}/node_exporter /usr/local/bin/
        sudo chmod +x /usr/local/bin/node_exporter
        rm -rf /tmp/node_exporter*
    fi
    
    success "Node Exporter installed."
}

# Install Prometheus
install_prometheus() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Installing Prometheus..." "⚙️"
    
    if ! command -v prometheus &>/dev/null; then
        local arch=$(uname -m)
        case "$arch" in
            x86_64) arch="amd64" ;;
            armv7l) arch="armv7" ;;
            aarch64) arch="arm64" ;;
        esac
        
        wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-${arch}.tar.gz -O /tmp/prometheus.tar.gz
        tar -xzf /tmp/prometheus.tar.gz -C /tmp
        sudo mv /tmp/prometheus-2.45.0.linux-${arch} /opt/prometheus
        sudo ln -sf /opt/prometheus/prometheus /usr/local/bin/prometheus
        rm -rf /tmp/prometheus*
    fi
    
    success "Prometheus installed."
}

# Install Grafana
install_grafana() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Installing Grafana..." "⚙️"
    
    if ! command -v grafana-server &>/dev/null; then
        wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
        echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
        sudo apt update
        sudo apt install -y grafana
    fi
    
    success "Grafana installed."
}

# Configure Prometheus for VNC monitoring
configure_prometheus() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Configuring Prometheus..." "⚙️"
    
    sudo mkdir -p /opt/prometheus/data
    
    sudo tee /opt/prometheus/prometheus.yml > /dev/null <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:$NODE_EXPORTER_PORT']
  
  - job_name: 'vnc_services'
    static_configs:
      - targets: ['localhost:$NOVNC_PORT', 'localhost:$TTYD_PORT', 'localhost:$VNC_PORT']
    metrics_path: /metrics
EOF
    
    success "Prometheus configured."
}

# Configure Grafana dashboard
configure_grafana() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Configuring Grafana..." "⚙️"
    
    # Configure Grafana to use Prometheus as datasource
    sudo tee /etc/grafana/grafana.ini > /dev/null <<EOF
[server]
http_port = $GRAFANA_PORT

[security]
admin_user = admin
admin_password = admin123

[users]
allow_sign_up = false
EOF
    
    success "Grafana configured."
}

# Start Node Exporter
start_node_exporter() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Starting Node Exporter..." "🚀"
    
    sudo systemctl enable node_exporter || {
        sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=prometheus
ExecStart=/usr/local/bin/node_exporter --web.listen-address=:$NODE_EXPORTER_PORT

[Install]
WantedBy=multi-user.target
EOF
        sudo useradd -rs /bin/false prometheus 2>/dev/null || true
        sudo systemctl daemon-reload
        sudo systemctl enable node_exporter
    }
    
    sudo systemctl start node_exporter || /usr/local/bin/node_exporter --web.listen-address=:$NODE_EXPORTER_PORT &
    
    success "Node Exporter started."
}

# Start Prometheus
start_prometheus() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Starting Prometheus..." "🚀"
    
    sudo systemctl enable prometheus || {
        sudo tee /etc/systemd/system/prometheus.service > /dev/null <<EOF
[Unit]
Description=Prometheus
After=network.target

[Service]
User=prometheus
ExecStart=/opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml --storage.tsdb.path=/opt/prometheus/data --web.listen-address=:$PROMETHEUS_PORT

[Install]
WantedBy=multi-user.target
EOF
        sudo useradd -rs /bin/false prometheus 2>/dev/null || true
        sudo chown -R prometheus:prometheus /opt/prometheus
        sudo systemctl daemon-reload
        sudo systemctl enable prometheus
    }
    
    sudo systemctl start prometheus || /opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml --web.listen-address=:$PROMETHEUS_PORT &
    
    success "Prometheus started on port $PROMETHEUS_PORT."
}

# Start Grafana
start_grafana() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Starting Grafana..." "🚀"
    
    sudo systemctl enable grafana-server
    sudo systemctl start grafana-server
    
    success "Grafana started on port $GRAFANA_PORT."
}

# Stop monitoring services
stop_monitoring() {
    [[ "$MONITORING_ENABLED" != "true" ]] && return
    
    log "yellow" "Stopping monitoring services..." "🛑"
    
    sudo systemctl stop grafana-server prometheus node_exporter 2>/dev/null || true
    pkill -f prometheus 2>/dev/null || true
    pkill -f node_exporter 2>/dev/null || true
    pkill -f grafana 2>/dev/null || true
    
    success "Monitoring services stopped."
}

# Get monitoring status
monitoring_status() {
    echo "=== Monitoring Status ==="
    echo "Node Exporter: $(pgrep -f node_exporter > /dev/null && echo 'Running' || echo 'Stopped')"
    echo "Prometheus: $(pgrep -f prometheus > /dev/null && echo 'Running' || echo 'Stopped')"
    echo "Grafana: $(pgrep -f grafana > /dev/null && echo 'Running' || echo 'Stopped')"
    echo ""
    echo "Access URLs:"
    echo "  Prometheus: http://localhost:$PROMETHEUS_PORT"
    echo "  Grafana: http://localhost:$GRAFANA_PORT (admin/admin123)"
}
