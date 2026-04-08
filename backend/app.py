import threading
import os
from flask import Flask, jsonify, request
from flask_cors import CORS

try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"[*] Scapy import failed (expected on cloud hosts without libpcap). Reason: {e}")
    sniff = None
    SCAPY_AVAILABLE = False
from detector import IntrusionDetector
from simulator import TrafficSimulator

app = Flask(__name__)
# Enable CORS for frontend connectivity
CORS(app)

# Global instances
detector = IntrusionDetector()
simulator = TrafficSimulator(detector)

# State flags
engine_state = {
    "is_running": False,
    "source": "None" # "Scapy" or "Simulator"
}
capture_thread = None

def _scapy_sniff_worker(interface=None):
    """Background worker specifically for Scapy."""
    def stop_filter(p):
        return not engine_state["is_running"]

    try:
        if not SCAPY_AVAILABLE:
            raise Exception("Scapy module not installed or missing OS dependencies.")
        
        engine_state["source"] = "Scapy"
        print("[*] Starting Scapy Sniffing on API request...")
        sniff(prn=detector.analyze_packet, store=False, iface=interface, stop_filter=stop_filter)
    except Exception as e:
        print(f"[!] Scapy failed to start. Reason: {e}")
        engine_state["source"] = "Simulator"
        print("[*] Falling back to Traffic Simulator.")
        simulator.start()

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Return summary and system state."""
    summary = detector.get_summary()
    return jsonify({
        "status": "success",
        "running": engine_state["is_running"],
        "source": engine_state["source"],
        "data": summary
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Return recent alerts."""
    return jsonify({
        "status": "success",
        "data": detector.alerts
    })

@app.route('/api/start', methods=['POST'])
def start_engine():
    """Starts the capture engine."""
    global capture_thread
    if engine_state["is_running"]:
        return jsonify({"status": "error", "message": "Engine is already running."}), 400

    # Optional interface parameter
    req_data = request.get_json(silent=True) or {}
    interface = req_data.get("interface", None)
    force_simulator = req_data.get("simulate", False)

    engine_state["is_running"] = True
    
    if force_simulator:
        engine_state["source"] = "Simulator"
        simulator.start()
    else:
        # Start Scapy thread. It will automatically fallback to simulator if it crashes.
        capture_thread = threading.Thread(target=_scapy_sniff_worker, args=(interface,))
        capture_thread.daemon = True
        capture_thread.start()

    return jsonify({"status": "success", "message": f"Engine started securely."})

@app.route('/api/stop', methods=['POST'])
def stop_engine():
    """Stops the capture engine."""
    if not engine_state["is_running"]:
        return jsonify({"status": "error", "message": "Engine is already stopped."}), 400

    engine_state["is_running"] = False
    
    if engine_state["source"] == "Simulator":
        simulator.stop()
    
    engine_state["source"] = "None"
    
    # Wait for Scapy thread to safely exit if it was active
    global capture_thread
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2)

    return jsonify({"status": "success", "message": "Engine stopped securely."})

if __name__ == '__main__':
    # Run Flask directly (Not for production, but optimal for this academic deployment layout)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
