FROM itsafeaturemythic/mythic_python_base:latest

RUN rm -rf /var/lib/apt/lists/* \
    && apt-get update \
    && apt-get install -y --no-install-recommends llvm \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz -o /tmp/zig.tar.xz \
    && echo "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c  /tmp/zig.tar.xz" | sha256sum -c \
    && tar -xJf /tmp/zig.tar.xz -C /usr/local \
    && ln -s /usr/local/zig-x86_64-linux-0.14.1/zig /usr/local/bin/zig \
    && rm /tmp/zig.tar.xz

RUN pip3 install donut-shellcode

WORKDIR /Mythic/

COPY . .

CMD ["python3", "main.py"]
