# About

EdgeBit agent is designed to track what packages are actively used by the system in order to ascertain which portions of the SBOM are relavent for vulnerability remediation.

# Building

To make it easier to deploy, the agent is a statically linked binary based on musl. As such, it is highly recommended to be built inside of a Docker container.

Use the following steps to build the agent.

1. Checkout the repo and pull down the submodules:
```
git clone https://github.com/edgebitio/edgebit-agent.git
cd edgebit-agent
git submodule init
git submodule update
```

2. Build the builder container:
```
cd build
docker build -t agent-builder .
```

3. Alias the docker run command to make it easier to reuse. The `cargo-git` and `cargo-registry` volumes are there to preserve the cache between builds.
```
alias agent-builder='docker run --rm -it -v "$(pwd)":/home/rust/src -v cargo-git:/home/rust/.cargo/git -v cargo-registry:/home/rust/.cargo/registry agent-builder'
```

4. Fix up permissions on the volumes:
```
agent-builder sudo chown -R rust:rust /home/rust/.cargo/git /home/rust/.cargo/registry
```

5. Build the agent
```
cd ..

# For debug build:
agent-builder cargo build

# For release build
agent-builder cargo build --release
```
