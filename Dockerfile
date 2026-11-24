# syntax=docker/dockerfile:1

# ---- build stage: compile ReconVigil and its dependencies into an isolated venv ----
FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build
RUN python -m venv /opt/venv
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN /opt/venv/bin/pip install .

# ---- runtime stage: no compilers, no pip cache, non-root ----
FROM python:3.12-slim
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 reconvigil \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin reconvigil \
    && mkdir /data \
    && chown 10001:10001 /data
COPY --from=builder /opt/venv /opt/venv
WORKDIR /data
USER 10001:10001
# Mount a volume at /data to persist the SQLite snapshot database and reports.
ENTRYPOINT ["reconvigil"]
CMD ["--help"]
