FROM nasqueron/rust-musl-builder

# Install libelf
RUN VERS=0.188 && \
    cd /home/rust/libs && \
    curl -L --output libelf-$VERS.tar.gz https://github.com/arachsys/libelf/archive/refs/tags/v$VERS.tar.gz && \
    tar xzf libelf-$VERS.tar.gz && cd libelf-$VERS && \
    export CC=musl-gcc PREFIX=/usr/local/musl C_INCLUDE_PATH=/usr/local/musl/include LIBRARY_PATH=/usr/local/musl/lib && \
    make libelf.a && sudo -E make install-static && \
    cd .. && rm -rf libelf-$VERS.tar.gz libelf-$VERS

RUN sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm

RUN sudo apt update && sudo apt -y install clang-10 libelf1 protobuf-compiler

RUN sudo ln -s /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so
RUN sudo ln -s /usr/lib/x86_64-linux-gnu/libelf.so.1 /usr/lib/x86_64-linux-gnu/libelf.so

ENV C_INCLUDE_PATH="/usr/include"
ENV EXTRA_CFLAGS="-I/usr/local/musl/include"
