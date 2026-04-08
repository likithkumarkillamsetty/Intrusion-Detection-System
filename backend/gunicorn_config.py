import os

# Render dynamically assigns a port via the PORT environment variable.
port = os.environ.get("PORT", "10000")

# Bind to 0.0.0.0 so the external Render ingress can reach it
bind = f"0.0.0.0:{port}"

# Free tier optimization: 1 worker, but multiple threads to handle concurrent requests
workers = 1
threads = 4

# Increase timeout to prevent 521 Cloudflare errors if the server is busy
timeout = 120
