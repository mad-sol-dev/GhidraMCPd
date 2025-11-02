# Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
uvicorn bridge.app:create_app --factory --port 8081
```

## Smoke test

```bash
bash bin/smoke.sh
```

## Health

* `GET /openapi.json` → OpenAPI document
* `GET /api/health.json` → optional 200 `{ok:true}` if present
