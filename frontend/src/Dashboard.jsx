import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Dashboard.css';

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchAlerts();
    fetchStats();
    // Refresh every 5 seconds
    const interval = setInterval(() => {
      fetchAlerts();
      fetchStats();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchAlerts = async () => {
    try {
      const response = await axios.get('http://localhost:8000/alerts');
      setAlerts(response.data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get('http://localhost:8000/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: '#FF0000',
      HIGH: '#FF6600',
      MEDIUM: '#FFAA00',
      LOW: '#00AA00'
    };
    return colors[severity] || '#666';
  };

  const handleRefresh = () => {
    setLoading(true);
    fetchAlerts();
    fetchStats();
    setTimeout(() => setLoading(false), 500);
  };

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>🛡️ Advanced IDS Dashboard</h1>
        <p>Real-time Intrusion Detection System</p>
      </header>

      {stats && (
        <div className="stats-container">
          <div className="stat-card">
            <h3>📊 Total Alerts</h3>
            <p className="stat-number">{stats.total_alerts}</p>
          </div>
        </div>
      )}

      <div className="controls">
        <button 
          className="refresh-btn"
          onClick={handleRefresh}
          disabled={loading}
        >
          🔄 Refresh
        </button>
      </div>

      <div className="alerts-section">
        <h2>🚨 Detected Alerts</h2>
        {alerts.length === 0 ? (
          <div className="no-alerts">
            ✅ No alerts detected - System is secure!
          </div>
        ) : (
          <table className="alerts-table">
            <thead>
              <tr>
                <th>⏰ Time</th>
                <th>🎯 Type</th>
                <th>⚠️ Severity</th>
                <th>🔗 Source IP</th>
                <th>🎯 Dest IP</th>
                <th>📝 Description</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr 
                  key={alert.id}
                  className={`alert-row severity-${alert.severity.toLowerCase()}`}
                  style={{
                    backgroundColor: getSeverityColor(alert.severity) + '20',
                    borderLeft: `4px solid ${getSeverityColor(alert.severity)}`
                  }}
                >
                  <td>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                  <td className="alert-type">{alert.alert_type}</td>
                  <td 
                    className="severity"
                    style={{ color: getSeverityColor(alert.severity), fontWeight: 'bold' }}
                  >
                    {alert.severity}
                  </td>
                  <td>{alert.src_ip}:{alert.src_port}</td>
                  <td>{alert.dst_ip}:{alert.dst_port}</td>
                  <td className="description">{alert.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}