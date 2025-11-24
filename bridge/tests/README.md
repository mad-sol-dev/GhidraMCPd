# Bridge test notes

New negative-path coverage focuses on project metadata routes and project rebasing:

- Project info/overview routes now assert envelope shapes for upstream transport failures and schema validation errors.
- Project rebasing rejects malformed `new_base` values, ensuring deterministic `{ok,data,errors[]}` envelopes for validation failures.
