# Gunicorn config: suppress the "Server: gunicorn/x.y.z" response header
# so we don't advertise the runtime even if a request reaches the app
# directly (bypassing Caddy). Caddy also strips this at the edge; this is
# defense in depth.
import gunicorn

gunicorn.SERVER_SOFTWARE = ""
