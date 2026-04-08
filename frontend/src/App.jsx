import { useState, useEffect } from 'react'
import './App.css'

const API_BASE = 'http://localhost:5000/api';

function App() {
  const [stats, setStats] = useState({ total_alerts: 0, total_packets: 0, attack_stats: {} })
  const [alerts, setAlerts] = useState([])
  const [engineState, setEngineState] = useState({ running: false, source: 'None' })
  const [loading, setLoading] = useState(false)

  const fetchMonitoringData = async () => {
    try {
      const statsRes = await fetch(`${API_BASE}/stats`);
      const statsData = await statsRes.json();

      const alertsRes = await fetch(`${API_BASE}/alerts`);
      const alertsData = await alertsRes.json();

      if (statsData.status === 'success') {
        setStats(statsData.data);
        setEngineState({ running: statsData.running, source: statsData.source });
      }

      if (alertsData.status === 'success') {
        setAlerts(alertsData.data.reverse()); // Show newest first
      }
    } catch (err) {
      console.error("Failed to fetch IDS data:", err);
    }
  };

  useEffect(() => {
    // Initial fetch
    fetchMonitoringData();
    // Polling every 2.5 seconds
    const interval = setInterval(fetchMonitoringData, 2500);
    return () => clearInterval(interval);
  }, []);

  const toggleEngine = async (action) => {
    setLoading(true);
    try {
      // For demo, forcefully use simulator button
      const payload = action === 'start' ? { simulate: true } : {};

      await fetch(`${API_BASE}/${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      // Force immediate refresh
      fetchMonitoringData();
    } catch (err) {
      console.error("Engine toggle failed", err);
    }
    setLoading(false);
  };

  // Render pure CSS chart bars dynamically
  const renderChartBars = () => {
    const data = stats.attack_stats;
    if (!data || Object.keys(data).length === 0) return <div className="empty-state">No attacks recorded yet</div>;

    // Find maximum count for scaling
    const maxCount = Math.max(...Object.values(data));

    return (
      <div className="chart-container">
        {Object.entries(data).map(([label, count]) => {
          // Normalize height compared to max
          const heightPercent = maxCount === 0 ? 0 : (count / maxCount) * 100;
          return (
            <div className="chart-bar-wrapper" key={label} title={`${label}: ${count}`}>
              <div style={{ color: "var(--accent-color)", fontWeight: "bold" }}>{count}</div>
              <div className="chart-bar" style={{ height: `${heightPercent}%`, minHeight: '4px' }}></div>
              <div className="chart-label">{label.replace(/_/g, " ")}</div>
            </div>
          )
        })}
      </div>
    );
  };

  return (
    <div className="app-container">
      <header>
        <h1>Shield IDS Dashboard</h1>
        <div className={`engine-status ${engineState.running ? 'running' : 'stopped'}`}>
          <span className="dot" style={{ height: '10px', width: '10px', borderRadius: '50%', background: engineState.running ? 'var(--success)' : 'var(--danger)', display: 'inline-block' }}></span>
          {engineState.running ? `Running (${engineState.source})` : 'Offline'}
        </div>
      </header>

      <section className="dashboard-cards">
        <div className="card">
          <div className="card-title">Total Packets Inspected</div>
          <div className="card-value">{stats.total_packets.toLocaleString()}</div>
        </div>
        <div className="card">
          <div className="card-title">Threat Alerts Detected</div>
          <div className="card-value" style={{ color: stats.total_alerts > 0 ? "var(--danger)" : "var(--text-primary)" }}>
            {stats.total_alerts.toLocaleString()}
          </div>
        </div>

        {/* We place controls into a card */}
        <div className="card">
          <div className="card-title">Engine Controls</div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>Controls the backend packet capture engine</p>
          <div className="controls">
            {!engineState.running ? (
              <button className="btn-primary" onClick={() => toggleEngine('start')} disabled={loading}>
                Start Simulator
              </button>
            ) : (
              <button className="btn-danger" onClick={() => toggleEngine('stop')} disabled={loading}>
                Stop Engine
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Chart Section */}
      {Object.keys(stats.attack_stats).length > 0 && (
        <section className="card" style={{ gridColumn: "1 / -1" }}>
          <div className="card-title">Attack Distribution Analytics</div>
          {renderChartBars()}
        </section>
      )}

      {/* Alerts Table */}
      <section className="alerts-section">
        <div className="alerts-header">
          <h2>Recent Threat Activity</h2>
        </div>
        <div style={{ overflowX: 'auto' }}>
          {alerts.length === 0 ? (
            <div className="empty-state">System is secure. No alerts detected.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Classification</th>
                  <th>Severity</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{alert.timestamp}</td>
                    <td style={{ fontFamily: 'monospace' }}>{alert.source_ip}</td>
                    <td>{alert.type}</td>
                    <td>
                      <span className={`badge ${alert.severity.toLowerCase()}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{alert.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  )
}

export default App
