FROM python:3.12-slim-bookworm AS weights
RUN python - <<'PY'
import hashlib
import urllib.request
url = 'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/91cad51170dc346986eccefdc2dd33a9da36ead9/qwen2.5-1.5b-instruct-q4_k_m.gguf'
h = hashlib.sha256()
with urllib.request.urlopen(url, timeout=120) as response, open('/model.gguf', 'wb') as target:
    while chunk := response.read(1024 * 1024):
        h.update(chunk)
        target.write(chunk)
assert h.hexdigest() == '6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e', 'Model checksum mismatch'
PY

FROM ghcr.io/ggml-org/llama.cpp:server@sha256:6257697a7f5d034b8fb499ddb07af3e250506352f94102054252a23f3b85e0af AS model
COPY --from=weights --chmod=444 /model.gguf /models/model.gguf
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/app/llama-server"]
CMD ["--model", "/models/model.gguf", "--alias", "qwen2.5-1.5b-instruct", "--host", "0.0.0.0", "--port", "8080", "--ctx-size", "4096", "--threads", "1", "--threads-batch", "1", "--parallel", "1", "--batch-size", "128", "--ubatch-size", "128", "--no-webui", "--no-warmup"]
