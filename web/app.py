#!/usr/bin/env python3
"""
Flask Dashboard - SOC Platform
Switched from eventlet to threading async_mode to eliminate the
EventletDeprecationWarning and avoid the eventlet end-of-life risk.
"""

from functools import wraps
from pathlib import Path
import sys
import threading

from flask import Flask, render_template, jsonify, request, abort
from flask_cors import CORS
from flask_socketio import SocketIO

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import (
    FLASK_HOST, FLASK_PORT, AUTO_REFRESH_INTERVAL,
    get_flask_secret_key, get_api_key, CORS_ALLOWED_ORIGINS,
)
from ingestion.database import SOCDatabase

app = Flask(__name__)
app.config['SECRET_KEY'] = get_flask_secret_key()

CORS(app, origins=CORS_ALLOWED_ORIGINS)

# FIX: async_mode='threading' replaces eventlet, which is deprecated and
# heading toward end-of-life. Threading mode uses the standard library,
# needs no monkey-patching, and works correctly with Python 3.14.
socketio = SocketIO(
    app,
    cors_allowed_origins=CORS_ALLOWED_ORIGINS,
    async_mode='threading',
)

db = SOCDatabase()
_API_KEY = get_api_key()

_background_task_started = False
_background_task_lock = threading.Lock()


# ------------------------------------------------------------------ #
# Auth                                                                 #
# ------------------------------------------------------------------ #

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        provided = request.headers.get('X-API-Key', '')
        if provided != _API_KEY:
            abort(401, description="Missing or invalid X-API-Key header")
        return f(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------------ #
# Routes                                                               #
# ------------------------------------------------------------------ #

@app.route('/')
def index():
    return render_template(
        'index.html',
        refresh_interval=AUTO_REFRESH_INTERVAL,
        api_key=_API_KEY,
    )


@app.route('/api/alerts')
@require_api_key
def api_alerts():
    status = request.args.get('status')
    limit  = min(int(request.args.get('limit', 50)), 500)
    return jsonify(db.get_alerts(limit=limit, status=status))


@app.route('/api/summary')
@require_api_key
def api_summary():
    return jsonify(db.get_summary())


@app.route('/api/honeypot')
@require_api_key
def api_honeypot():
    alerts = db.get_alerts(limit=200, status=None)
    hits   = [a for a in alerts if a.get('source_component') == 'honeypot']
    by_service = {}
    for h in hits:
        svc = h.get('attack_type', 'Honeypot-UNKNOWN').replace('Honeypot-', '')
        by_service[svc] = by_service.get(svc, 0) + 1
    top_ips = {}
    for h in hits:
        ip = h.get('source_ip', 'unknown')
        top_ips[ip] = top_ips.get(ip, 0) + 1
    top_ips_sorted = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify({
        'total_hits': len(hits),
        'by_service': by_service,
        'top_ips':    [{'ip': ip, 'count': c} for ip, c in top_ips_sorted],
        'recent':     hits[:20],
    })


@app.route('/api/alerts/<alert_id>/ack', methods=['POST'])
@require_api_key
def api_ack_alert(alert_id):
    body = request.get_json(silent=True) or {}
    acknowledged_by = body.get('acknowledged_by', 'unknown')
    ok = db.acknowledge_alert(alert_id, acknowledged_by)
    if not ok:
        abort(500, description="Failed to acknowledge alert")
    socketio.emit('refresh_data', {})
    return jsonify({'status': 'ok'})


@app.route('/api/alerts/<alert_id>/comment', methods=['POST'])
@require_api_key
def api_comment_alert(alert_id):
    body    = request.get_json(silent=True) or {}
    comment = body.get('comment', '').strip()
    if not comment:
        abort(400, description="comment is required")
    ok = db.add_comment(alert_id, comment)
    if not ok:
        abort(500, description="Failed to add comment")
    return jsonify({'status': 'ok'})


@app.route('/api/alerts/<alert_id>/status', methods=['POST'])
@require_api_key
def api_update_status(alert_id):
    body   = request.get_json(silent=True) or {}
    status = body.get('status')
    if status not in ('new', 'acknowledged', 'investigating', 'closed', 'false_positive'):
        abort(400, description="invalid status value")
    ok = db.update_status(alert_id, status)
    if not ok:
        abort(500, description="Failed to update status")
    socketio.emit('refresh_data', {})
    return jsonify({'status': 'ok'})


@app.route('/api/geo')
@require_api_key
def api_geo():
    """Return recent alerts with lat/lon for the world map."""
    alerts = db.get_alerts(limit=500)
    points = []
    for a in alerts:
        lat = a.get('latitude') or 0.0
        lon = a.get('longitude') or 0.0
        if lat == 0.0 and lon == 0.0:
            continue   # no geo data yet
        points.append({
            'lat':          lat,
            'lon':          lon,
            'ip':           a.get('source_ip', ''),
            'country':      a.get('country', 'Unknown'),
            'city':         a.get('city', ''),
            'attack_type':  a.get('attack_type', ''),
            'severity':     a.get('severity', ''),
            'method':       a.get('detection_method', 'rule'),
            'timestamp':    a.get('timestamp', ''),
        })
    return jsonify(points)


# ------------------------------------------------------------------ #
# Background refresh — started exactly once, not per client connect   #
# ------------------------------------------------------------------ #

def _background_refresh() -> None:
    """Push a refresh event to all connected dashboard clients periodically.
    Runs in a plain daemon thread (threading async_mode doesn't use
    socketio.start_background_task the same way eventlet did)."""
    import time
    while True:
        time.sleep(AUTO_REFRESH_INTERVAL)
        socketio.emit('refresh_data', {})


@socketio.on('connect')
def handle_connect():
    global _background_task_started
    with _background_task_lock:
        if not _background_task_started:
            t = threading.Thread(
                target=_background_refresh,
                name='DashboardRefresh',
                daemon=True,
            )
            t.start()
            _background_task_started = True


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

if __name__ == '__main__':
    print(f"🚀 Dashboard: http://{FLASK_HOST}:{FLASK_PORT}")
    print(f"🔑 API key (X-API-Key header, also saved to storage/.api_key): {_API_KEY}")
    socketio.run(
        app,
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=False,
        allow_unsafe_werkzeug=True,
        # FIX: explicit async_mode here matches the SocketIO() constructor above.
        # No need for eventlet or gevent to be installed.
    )
