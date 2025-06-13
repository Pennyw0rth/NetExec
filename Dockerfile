# --- Build Stage ---
FROM python:3.13-slim-bookworm AS builder
ENV TAG=1.4.0
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

WORKDIR /usr/src/netexec

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libffi-dev \
        libxml2-dev \
        libxslt-dev \
        libssl-dev \
        openssl \
        autoconf \
        g++ \
        python3-dev \
        curl \
        git \
        unzip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone --depth 1 --branch v${TAG} https://github.com/Pennyw0rth/NetExec.git . \
    && pip install .

FROM python:3.13-slim-bookworm

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

WORKDIR /usr/src/netexec

COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["nxc"]
