from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features.collect import execute_collect
from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.logging import SafetyLimitExceeded, request_scope
from .._shared import envelope_error, envelope_ok, envelope_response
from ..validators import validate_payload
from ._common import RouteDependencies


def create_collect_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def collect_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "collect",
            logger=deps.logger,
            extra={"path": "/api/collect.json"},
        ):
            try:
                data = await deps.validated_json_body(
                    request, "collect.request.v1.json"
                )
            except ValueError as exc:
                return envelope_response(envelope_error(ErrorCode.INVALID_REQUEST, str(exc)))

            queries_raw = data.get("queries")
            queries: Sequence[Mapping[str, object]]
            if queries_raw is None:
                queries = []
            else:
                if not isinstance(queries_raw, list) or any(
                    not isinstance(item, Mapping) for item in queries_raw
                ):
                    return envelope_response(
                        envelope_error(
                            ErrorCode.INVALID_REQUEST,
                            "queries must be an array of objects",
                        )
                    )
                queries = queries_raw

            result_budget = data.get("result_budget")

            try:
                base_payload = execute_collect(
                    client,
                    queries,
                    result_budget=result_budget
                    if isinstance(result_budget, Mapping)
                    else None,
                )
            except SafetyLimitExceeded as exc:
                return envelope_response(
                    envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
                )
            except (KeyError, TypeError, ValueError) as exc:
                return envelope_response(
                    envelope_error(ErrorCode.INVALID_REQUEST, str(exc))
                )

            projects_raw = data.get("projects")
            if projects_raw is None:
                projects_list: List[Mapping[str, Any]] = []
            elif isinstance(projects_raw, list):
                projects_list = [
                    entry
                    for entry in projects_raw
                    if isinstance(entry, Mapping)
                ]
                if len(projects_list) != len(projects_raw):
                    return envelope_response(
                        envelope_error(
                            ErrorCode.INVALID_REQUEST,
                            "projects must be an array of objects",
                        )
                    )
            else:
                return envelope_response(
                    envelope_error(
                        ErrorCode.INVALID_REQUEST, "projects must be an array"
                    )
                )

            response_payload: Dict[str, Any] = {
                "queries": base_payload.get("queries", []),
                "meta": dict(base_payload.get("meta", {})),
            }

            aggregate_tokens = int(response_payload["meta"].get("estimate_tokens", 0) or 0)

            if projects_list:
                project_results: List[Dict[str, Any]] = []
                for project_entry in projects_list:
                    project_id = project_entry.get("id")
                    if not isinstance(project_id, str) or not project_id:
                        return envelope_response(
                            envelope_error(
                                ErrorCode.INVALID_REQUEST,
                                "project id must be a non-empty string",
                            )
                        )

                    project_queries_raw = project_entry.get("queries")
                    if project_queries_raw is None:
                        project_queries: Sequence[Mapping[str, object]] = []
                    elif isinstance(project_queries_raw, list) and not any(
                        not isinstance(item, Mapping) for item in project_queries_raw
                    ):
                        project_queries = project_queries_raw
                    else:
                        return envelope_response(
                            envelope_error(
                                ErrorCode.INVALID_REQUEST,
                                "project queries must be an array of objects",
                            )
                        )

                    project_budget = project_entry.get("result_budget")
                    project_url_raw = project_entry.get("ghidra_url") or project_entry.get(
                        "base_url"
                    )
                    project_client = client
                    project_url: str | None = None
                    if project_url_raw is not None:
                        project_url = str(project_url_raw)
                        project_client = deps.client_factory()
                        if hasattr(project_client, "base_url"):
                            try:
                                project_client.base_url = (
                                    project_url
                                    if project_url.endswith("/")
                                    else f"{project_url}/"
                                )
                            except AttributeError:
                                pass

                    try:
                        project_payload = execute_collect(
                            project_client,
                            project_queries,
                            result_budget=project_budget
                            if isinstance(project_budget, Mapping)
                            else None,
                        )
                    except SafetyLimitExceeded as exc:
                        if project_client is not client:
                            project_client.close()
                        return envelope_response(
                            envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
                        )
                    except (KeyError, TypeError, ValueError) as exc:
                        if project_client is not client:
                            project_client.close()
                        return envelope_response(
                            envelope_error(ErrorCode.INVALID_REQUEST, str(exc))
                        )

                    project_meta = dict(project_payload.get("meta", {}))
                    estimate = int(project_meta.get("estimate_tokens", 0) or 0)
                    aggregate_tokens += estimate
                    if project_url is not None:
                        project_meta.setdefault("ghidra_url", project_url)

                    project_result: Dict[str, Any] = {
                        "id": project_id,
                        "queries": project_payload.get("queries", []),
                        "meta": project_meta,
                    }

                    metadata = project_entry.get("metadata")
                    if metadata is not None:
                        project_result["metadata"] = metadata

                    project_results.append(project_result)

                    if project_client is not client:
                        project_client.close()

                response_payload["projects"] = project_results

            response_payload["meta"]["estimate_tokens"] = aggregate_tokens

            valid, errors = validate_payload("collect.v1.json", response_payload)
            if valid:
                return envelope_response(envelope_ok(response_payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [Route("/api/collect.json", collect_route, methods=["POST"])]


__all__ = ["create_collect_routes"]
