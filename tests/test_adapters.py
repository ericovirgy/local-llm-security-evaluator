from __future__ import annotations

import pytest

from llmsec.adapters import (
    AdapterError,
    GenerationParams,
    OllamaAdapter,
    OpenAICompatAdapter,
    ReferenceAdapter,
    make_adapter,
)
from llmsec.adapters.http import MAX_RESPONSE_BYTES, is_loopback_host, validate_base_url
from llmsec.corpus.model import Message, Role
from tests.conftest import FakeServer, json_response, ollama_routes

MSGS = (Message(Role.SYSTEM, "sys"), Message(Role.USER, "hi"))


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("localhost", True),
        ("127.0.0.1", True),
        ("127.8.9.10", True),
        ("::1", True),
        ("[::1]", True),
        ("10.0.0.5", False),
        ("example.com", False),
        ("0.0.0.0", False),
    ],
)
def test_loopback_detection(host: str, expected: bool) -> None:
    assert is_loopback_host(host) is expected


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://127.0.0.1", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("http://user:pw@127.0.0.1:11434", "credentials"),
        ("http://127.0.0.1:11434?x=1", "query"),
        ("http://192.168.1.20:11434", "not a loopback"),
        ("https://api.example.com/v1", "not a loopback"),
    ],
)
def test_endpoint_validation(url: str, message: str) -> None:
    with pytest.raises(AdapterError, match=message):
        validate_base_url(url, allow_remote=False)


def test_remote_endpoint_requires_explicit_opt_in() -> None:
    assert validate_base_url("http://192.168.1.20:11434/", allow_remote=True) == (
        "http://192.168.1.20:11434"
    )


def test_ollama_list_describe_and_chat(fake_server: FakeServer) -> None:
    ollama_routes(fake_server, lambda msgs: f"echo:{msgs[-1]['content']}")
    adapter = OllamaAdapter(fake_server.url)
    models = adapter.list_models()
    assert [m.name for m in models] == ["fake-model:1b"]
    info = adapter.describe("fake-model:1b")
    assert (info.digest, info.parameter_size, info.quantization) == ("abc123", "1B", "Q4_K_M")
    out = adapter.chat(
        "fake-model:1b",
        MSGS,
        GenerationParams(temperature=0.0, seed=7, max_tokens=64, num_ctx=4096),
    )
    assert out.text == "echo:hi"
    assert (out.finish_reason, out.prompt_tokens, out.completion_tokens) == ("stop", 10, 5)
    body = fake_server.requests[-1]["body"]
    assert body["stream"] is False
    assert body["options"] == {"temperature": 0.0, "seed": 7, "num_predict": 64, "num_ctx": 4096}
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
    ]


def test_ollama_unknown_model(fake_server: FakeServer) -> None:
    ollama_routes(fake_server, lambda m: "x")
    with pytest.raises(AdapterError, match="not available"):
        OllamaAdapter(fake_server.url).describe("missing:7b")


@pytest.mark.parametrize(
    ("route", "message"),
    [
        (lambda b: (200, b"<html>not json</html>", {}), "not valid JSON"),
        (lambda b: (200, b"[1,2,3]", {}), "not a JSON object"),
        (lambda b: json_response({"message": {"role": "assistant"}}), "content"),
        (lambda b: json_response({"message": "flat string"}), "expected an object"),
        (lambda b: json_response({"error": "model not loaded"}), "model not loaded"),
        (lambda b: json_response({"error": "boom"}, status=500), "HTTP 500"),
        (lambda b: (302, b"", {"Location": "http://example.com/steal"}), "HTTP 302"),
        (lambda b: (200, b'{"a":"' + b"x" * (MAX_RESPONSE_BYTES + 10) + b'"}', {}), "exceeds"),
    ],
)
def test_malformed_ollama_responses_raise_adapter_error(
    fake_server: FakeServer, route, message: str
) -> None:
    fake_server.routes[("POST", "/api/chat")] = route
    with pytest.raises(AdapterError, match=message):
        OllamaAdapter(fake_server.url).chat("m", MSGS, GenerationParams())


def test_unreachable_endpoint() -> None:
    adapter = OllamaAdapter("http://127.0.0.1:9", timeout=2)
    with pytest.raises(AdapterError, match="cannot reach"):
        adapter.list_models()


def test_environment_proxies_are_ignored(fake_server: FakeServer, monkeypatch) -> None:
    ollama_routes(fake_server, lambda m: "direct")
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    assert OllamaAdapter(fake_server.url).chat("m", MSGS, GenerationParams()).text == "direct"


def test_openai_compatible_adapter(fake_server: FakeServer, monkeypatch) -> None:
    fake_server.routes[("GET", "/v1/models")] = lambda b: json_response(
        {"data": [{"id": "local-gguf", "owned_by": "me"}]}
    )
    fake_server.routes[("POST", "/v1/chat/completions")] = lambda b: json_response(
        {
            "choices": [
                {"message": {"role": "assistant", "content": "hello"}, "finish_reason": "length"}
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
    )
    monkeypatch.setenv("LLMSEC_TEST_KEY", "sk-local-test")
    adapter = OpenAICompatAdapter(f"{fake_server.url}/v1", api_key_env="LLMSEC_TEST_KEY")
    assert [m.name for m in adapter.list_models()] == ["local-gguf"]
    out = adapter.chat("local-gguf", MSGS, GenerationParams(max_tokens=9, seed=3))
    assert out.text == "hello"
    assert out.truncated
    req = fake_server.requests[-1]
    assert req["headers"]["Authorization"] == "Bearer sk-local-test"
    assert req["body"]["max_tokens"] == 9 and req["body"]["seed"] == 3
    assert "sk-local-test" not in adapter.endpoint_label()


def test_openai_missing_api_key_env(monkeypatch) -> None:
    monkeypatch.delenv("LLMSEC_NOPE", raising=False)
    with pytest.raises(AdapterError, match="LLMSEC_NOPE"):
        OpenAICompatAdapter("http://127.0.0.1:1/v1", api_key_env="LLMSEC_NOPE")


def test_openai_no_choices(fake_server: FakeServer) -> None:
    fake_server.routes[("POST", "/v1/chat/completions")] = lambda b: json_response({"choices": []})
    with pytest.raises(AdapterError, match="no choices"):
        OpenAICompatAdapter(f"{fake_server.url}/v1").chat("m", MSGS, GenerationParams())


def test_reference_responders() -> None:
    ref = ReferenceAdapter()
    assert ref.chat("refuse", MSGS, GenerationParams()).text.startswith("I can't")
    assert ref.chat("echo", MSGS, GenerationParams()).text == "sys\n\nhi"
    with pytest.raises(AdapterError):
        ref.describe("gpt")


def test_make_adapter_rejects_unknown_kind() -> None:
    with pytest.raises(AdapterError, match="unknown adapter"):
        make_adapter("cloud")
