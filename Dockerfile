FROM python:3.13-slim-bookworm AS builder
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

WORKDIR /usr/src/netexec

RUN apt update && \
    apt install -y --no-install-recommends \
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
    && apt clean && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone https://github.com/Pennyw0rth/NetExec.git . \
    && pip install .

FROM python:3.13-slim-bookworm

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

WORKDIR /usr/src/netexec

COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

RUN apt update && \
    apt install -y --no-install-recommends \
        openssl \
    && apt clean && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["nxc"]
