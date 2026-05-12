#!/bin/sh
echo "=== STARTING APP ==="
echo "PORT=$PORT"
echo "DATABASE_URL present: $([ -n "$DATABASE_URL" ] && echo YES || echo NO)"
exec uvicorn api:app --host 0.0.0.0 --port "${PORT:-8000}"
