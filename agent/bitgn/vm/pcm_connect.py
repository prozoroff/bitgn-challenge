"""ConnectRPC sync client for PcmRuntime service."""

from connectrpc.client import ConnectClientSync
from connectrpc.method import IdempotencyLevel, MethodInfo

from bitgn.vm import pcm_pb2 as pb


class PcmRuntimeClientSync:
    def __init__(self, address: str):
        self._client = ConnectClientSync(address)

    def _method(self, name, input_type, output_type):
        return MethodInfo(
            name=name,
            service_name="bitgn.vm.pcm.PcmRuntime",
            input=input_type,
            output=output_type,
            idempotency_level=IdempotencyLevel.UNKNOWN,
        )

    def read(self, request: pb.ReadRequest) -> pb.ReadResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Read", pb.ReadRequest, pb.ReadResponse),
        )

    def write(self, request: pb.WriteRequest) -> pb.WriteResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Write", pb.WriteRequest, pb.WriteResponse),
        )

    def delete(self, request: pb.DeleteRequest) -> pb.DeleteResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Delete", pb.DeleteRequest, pb.DeleteResponse),
        )

    def mk_dir(self, request: pb.MkDirRequest) -> pb.MkDirResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("MkDir", pb.MkDirRequest, pb.MkDirResponse),
        )

    def move(self, request: pb.MoveRequest) -> pb.MoveResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Move", pb.MoveRequest, pb.MoveResponse),
        )

    def list(self, request: pb.ListRequest) -> pb.ListResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("List", pb.ListRequest, pb.ListResponse),
        )

    def tree(self, request: pb.TreeRequest) -> pb.TreeResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Tree", pb.TreeRequest, pb.TreeResponse),
        )

    def find(self, request: pb.FindRequest) -> pb.FindResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Find", pb.FindRequest, pb.FindResponse),
        )

    def search(self, request: pb.SearchRequest) -> pb.SearchResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Search", pb.SearchRequest, pb.SearchResponse),
        )

    def context(self, request: pb.ContextRequest) -> pb.ContextResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Context", pb.ContextRequest, pb.ContextResponse),
        )

    def answer(self, request: pb.AnswerRequest) -> pb.AnswerResponse:
        return self._client.execute_unary(
            request=request,
            method=self._method("Answer", pb.AnswerRequest, pb.AnswerResponse),
        )
