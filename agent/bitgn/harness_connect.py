"""ConnectRPC sync client for HarnessService."""

from __future__ import annotations

from connectrpc.client import ConnectClientSync
from connectrpc.interceptor import MetadataInterceptorSync
from connectrpc.method import IdempotencyLevel, MethodInfo
from connectrpc.request import RequestContext

from bitgn import harness_pb2 as pb


class _BitGnApiKeyInterceptor(MetadataInterceptorSync[None]):
    """Adds BitGN API key to every Harness RPC (server may also accept api_key in newer protos)."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def on_start_sync(self, ctx: RequestContext) -> None:
        ctx.request_headers()["authorization"] = f"Bearer {self._api_key}"
        return None

    def on_end_sync(
        self, token: None, ctx: RequestContext, error: Exception | None
    ) -> None:
        return


class HarnessServiceClientSync:
    def __init__(self, address: str, *, api_key: str | None = None):
        interceptors = (_BitGnApiKeyInterceptor(api_key),) if api_key else ()
        self._client = ConnectClientSync(address, interceptors=interceptors)

    def _method(self, name, input_type, output_type):
        return MethodInfo(
            name=name,
            service_name="bitgn.harness.HarnessService",
            input=input_type,
            output=output_type,
            idempotency_level=IdempotencyLevel.UNKNOWN,
        )

    def status(self, request: pb.StatusRequest) -> pb.StatusResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Status", pb.StatusRequest, pb.StatusResponse),
        )

    def get_benchmark(self, request: pb.GetBenchmarkRequest) -> pb.GetBenchmarkResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("GetBenchmark", pb.GetBenchmarkRequest, pb.GetBenchmarkResponse),
        )

    def start_run(self, request: pb.StartRunRequest) -> pb.StartRunResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("StartRun", pb.StartRunRequest, pb.StartRunResponse),
        )

    def get_run(self, request: pb.GetRunRequest) -> pb.GetRunResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("GetRun", pb.GetRunRequest, pb.GetRunResponse),
        )

    def submit_run(self, request: pb.SubmitRunRequest) -> pb.SubmitRunResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("SubmitRun", pb.SubmitRunRequest, pb.SubmitRunResponse),
        )

    def start_playground(self, request: pb.StartPlaygroundRequest) -> pb.StartPlaygroundResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("StartPlayground", pb.StartPlaygroundRequest, pb.StartPlaygroundResponse),
        )

    def start_trial(self, request: pb.StartTrialRequest) -> pb.StartTrialResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("StartTrial", pb.StartTrialRequest, pb.StartTrialResponse),
        )

    def get_trial(self, request: pb.GetTrialRequest) -> pb.GetTrialResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("GetTrial", pb.GetTrialRequest, pb.GetTrialResponse),
        )

    def end_trial(self, request: pb.EndTrialRequest) -> pb.EndTrialResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("EndTrial", pb.EndTrialRequest, pb.EndTrialResponse),
        )
