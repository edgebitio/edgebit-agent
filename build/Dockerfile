# Use Ubuntu 18.04 LTS as our base image.
FROM ubuntu:20.04

# The Rust toolchain to use when building our image.  Set by `hooks/build`.
ARG TOOLCHAIN=stable

# The target architecture
ARG ARCH=x86_64

ARG ZLIB_VERSION=1.2.13

ARG LIBELF_VERSION=0.188 

ENV CC=musl-gcc

# Make sure we have basic dev tools for building C libraries.  Our goal here is
# to support the musl-libc builds and Cargo builds needed for a large selection
# of the most popular crates.
#
# We also set up a `rust` user by default. This user has sudo privileges if you
# need to install any more software.
RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -yq \
        build-essential \
        cmake \
        curl \
        file \
        musl-dev \
        musl-tools \
        linux-libc-dev \
        pkgconf \
        sudo \
        unzip \
        xutils-dev \
        && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    useradd rust --user-group --create-home --shell /bin/bash --groups sudo

# Static linking for C++ code
RUN ln -s "/usr/bin/g++" "/usr/bin/musl-g++"

RUN echo "Building zlib" && \
    cd /tmp && \
    curl -fLO "http://zlib.net/zlib-$ZLIB_VERSION.tar.gz" && \
    tar xzf "zlib-$ZLIB_VERSION.tar.gz" && cd "zlib-$ZLIB_VERSION" && \
    ./configure --static --prefix=/usr/local/musl && \
    make && make install && \
    rm -r /tmp/*

# Install libelf
RUN cd /tmp && \
    curl -L https://github.com/arachsys/libelf/archive/refs/tags/v$LIBELF_VERSION.tar.gz | tar xz && \
    cd libelf-$LIBELF_VERSION && \
    export PREFIX=/usr/local/musl C_INCLUDE_PATH=/usr/local/musl/include LIBRARY_PATH=/usr/local/musl/lib && \
    make libelf.a && make install-static && \
    rm -r /tmp/*

# Set up our path with all our binary directories, including those for the
# musl-gcc toolchain and for our Rust toolchain.
#
# We use the instructions at https://github.com/rust-lang/rustup/issues/2383
# to install the rustup toolchain as root.
ENV RUSTUP_HOME=/opt/rust/rustup \
    PATH=/home/rust/.cargo/bin:/opt/rust/cargo/bin:/usr/local/musl/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Install our Rust toolchain and the `musl` target.  We patch the
# command-line we pass to the installer so that it won't attempt to
# interact with the user or fool around with TTYs.  We also set the default
# `--target` to musl so that our users don't need to keep overriding it
# manually.
RUN curl https://sh.rustup.rs -sSf | \
    env CARGO_HOME=/opt/rust/cargo \
        sh -s -- -y --default-toolchain $TOOLCHAIN --profile minimal --no-modify-path && \
    env CARGO_HOME=/opt/rust/cargo \
        rustup component add rustfmt && \
    env CARGO_HOME=/opt/rust/cargo \
        rustup component add clippy && \
    env CARGO_HOME=/opt/rust/cargo \
        rustup target add $ARCH-unknown-linux-musl
ADD cargo-config.toml /opt/rust/cargo/config

# Set up our environment variables so that we cross-compile using musl-libc by
# default.
ENV X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=/usr/local/musl/ \
    X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1 \
    AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR=/usr/local/musl/ \
    AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1 \
    PKG_CONFIG_ALLOW_CROSS=true \
    PKG_CONFIG_ALL_STATIC=true \
    LIBZ_SYS_STATIC=1 \
    TARGET=musl

RUN ln -s /usr/include/${ARCH}-linux-gnu/asm /usr/include/${ARCH}-linux-musl/asm && \
    ln -s /lib/${ARCH}-linux-gnu/libz.so.1 /lib/${ARCH}-linux-gnu/libz.so && \
    ln -s /usr/lib/${ARCH}-linux-gnu/libelf.so.1 /usr/lib/${ARCH}-linux-gnu/libelf.so

RUN apt update && apt -y install clang-10 libelf1 protobuf-compiler libprotobuf-dev

# Allow sudo without a password.
ADD sudoers /etc/sudoers.d/nopasswd

# Run all further code as user `rust`, create our working directories, install
# our config file, and set up our credential helper.
#
# You should be able to switch back to `USER root` from another `Dockerfile`
# using this image if you need to do so.
USER rust
RUN mkdir -p /home/rust/libs /home/rust/src /home/rust/.cargo && \
    ln -s /opt/rust/cargo/config /home/rust/.cargo/config

# Expect our source code to live in /home/rust/src.  We'll run the build as
# user `rust`, which will be uid 1000, gid 1000 outside the container.
WORKDIR /home/rust/src

ENV CARGO_BUILD_TARGET="$ARCH-unknown-linux-musl"
ENV C_INCLUDE_PATH="/usr/include"
ENV EXTRA_CFLAGS="-fPIC -I/usr/local/musl/include"
