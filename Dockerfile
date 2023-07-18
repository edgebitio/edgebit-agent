FROM agent-builder:latest AS build

RUN touch /tmp/dummy

COPY . /root/src

RUN cargo fmt --check

# Treat warnings as errors to make it fail on suggestions
RUN cargo clippy -- -Dwarnings

RUN cargo build --release --target "$(cat /etc/arch)-unknown-linux-musl" && \
    ln -s "$(cat /etc/arch)-unknown-linux-musl/release/edgebit-agent" "target/edgebit-agent"

RUN cargo test --release --target "$(cat /etc/arch)-unknown-linux-musl"

# Downloads Syft and make .rpm/deb packages
RUN cd dist && make all

# ------------------------------------
FROM scratch

COPY --from=build /root/src/target/edgebit-agent /opt/edgebit/edgebit-agent
COPY --from=build /root/src/dist/syft/ /opt/edgebit/syft/
COPY --from=build /root/src/dist/syft.yaml /opt/edgebit/syft.yaml

# Due to a few bugs in Rust's AWS bindings, it needs native certs even
# though it won't use them since IMDS is over HTTP
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Create the basic directory structure.
# Since the image is based on scratch, there's no "mkdir" to run.
COPY --from=build /tmp/dummy /etc/edgebit/
COPY --from=build /tmp/dummy /tmp/
COPY --from=build /tmp/dummy /run/
COPY --from=build /tmp/dummy /var/lib/edgebit/

ENV EDGEBIT_SYFT_PATH=/opt/edgebit/syft/syft
ENV EDGEBIT_SYFT_CONFIG=/opt/edgebit/syft.yaml

ENTRYPOINT [ "/opt/edgebit/edgebit-agent", "--host-root", "/host" ]
