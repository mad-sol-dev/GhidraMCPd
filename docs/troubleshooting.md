# Troubleshooting

- **409 on `/sse`**: by design; only one active client.
- **425 on `/messages`**: session not ready; connect SSE and wait for readiness.
- **Noisy `CancelledError` on shutdown**: ensure you are on a recent build; the bridge suppresses expected cancellations.
- **Adapter error**: unknown optional adapter → check `BRIDGE_OPTIONAL_ADAPTERS` names.
