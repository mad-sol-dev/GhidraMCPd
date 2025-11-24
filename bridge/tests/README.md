# Bridge test notes

Negative-path coverage now spans project metadata routes, project rebasing, and program selection helpers:

- Project info/overview routes assert envelope shapes for upstream transport failures and schema validation errors.
- Project rebasing rejects malformed `new_base` values, ensuring deterministic `{ok,data,errors[]}` envelopes for validation failures.
- Program selection MCP tools exercise schema validation, deterministic defaults, and oversized-limit/error envelopes for malformed parameters.
