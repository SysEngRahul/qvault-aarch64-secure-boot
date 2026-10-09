FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=1700000000
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu qemu-system-arm \
    device-tree-compiler ipxe-qemu make python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /qvault
COPY . .
CMD ["make", "all", "test"]
