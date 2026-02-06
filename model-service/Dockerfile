# CUDA 12.8.1 devel for SM120/Blackwell (B100/B200/RTX 50xx) support
# Devel image needed for Triton kernel compilation (MXFP4 quantization)
FROM nvidia/cuda:12.8.1-cudnn-devel-ubuntu24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV TORCH_CUDA_ARCH_LIST="8.0;8.6;8.9;9.0;12.0"

# Install Python and uv (fast package installer)
RUN apt-get update && apt-get install -y \
    python3.12 \
    python3.12-dev \
    python3.12-venv \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create and activate virtual environment
ENV VIRTUAL_ENV=/opt/venv
RUN python3.12 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /app

# Install dependencies with uv (10-100x faster than pip)
COPY requirements.txt .
RUN uv pip install --no-cache --index-strategy unsafe-best-match -r requirements.txt

COPY . .

# Create non-root user
RUN useradd -m -u 1001 appuser && \
    mkdir -p /home/appuser/.cache/huggingface && \
    chown -R appuser:appuser /home/appuser/.cache /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
