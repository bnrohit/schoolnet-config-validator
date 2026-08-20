FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Runtime-only diagnostic utilities. Python dependencies used by SchoolNet ship
# wheels for the supported runtime, so a compiler toolchain is not required in
# the production image. Keeping gcc/build-essential out saves substantial disk
# space on small operations hosts.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       dnsutils \
       iproute2 \
       iputils-ping \
       traceroute \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --upgrade pip \
    && pip install --no-compile -r requirements.txt

COPY backend/ ./
COPY configs/ ./configs/

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health').read()"

CMD ["uvicorn", "secure_application:app", "--host", "0.0.0.0", "--port", "8000"]
