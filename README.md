# About

EdgeBit agent is designed to track what packages are actively used by the system in order to ascertain which portions of the SBOM are relavent for vulnerability remediation.

# Building

To make it easier to deploy, the agent is a statically linked binary based on musl. As such, it is highly recommended to be built inside of a Docker container.

Use the following steps to build the agent.

1. Checkout the repo and pull down the submodules:
```
git clone https://github.com/edgebitio/edgebit-agent.git
cd edgebit-agent
git submodule update --init
```

2. Build the builder container:
```
cd build
docker build -t agent-builder .
```

3. Alias the docker run command to make it easier to reuse. The `cargo-git` and `cargo-registry` volumes are there to preserve the cache between builds.
```
alias agent-builder='docker run --rm -it -v "$(pwd)":/root/src -v cargo-git:/root/.cargo/git -v cargo-registry:/root/.cargo/registry agent-builder'
```

5. Build the agent
```
cd ..

# For debug build:
agent-builder cargo build

# For release build
agent-builder cargo build --release
```

# Docker based deployment

## Building a Docker container

To build a Docker image containing the agent, follow the steps below:

1. Checkout the repo and pull down the submodules:
```
git clone https://github.com/edgebitio/edgebit-agent.git
cd edgebit-agent
git submodule update --init
```

2. Build the builder container:
```
cd build
docker build -t agent-builder .
```

3. Build the Docker image:
```
cd ..
docker build -t edgebit-agent .
```

## Running the Docker container

You can use a configuration file and bind mount it into the container at `/etc/edgebit/config.yaml`.
However for simple deployments, it can be easier to use environment variables to supply the URL and the ID (deployment token):

```
docker run \
  --name edgebit-agent \
  --rm \
  -d \
  --privileged \
  --pid host \
  --mount "type=bind,source=/,destination=/host" \
  --mount "type=bind,source=/etc/edgebit,destination=/etc/edgebit" \
  --mount "type=bind,source=/sys/kernel/debug,destination=/sys/kernel/debug" \
  --mount "type=bind,source=/run/docker.sock,destination=/run/docker.sock" \
  --mount "type=volume,source=var-edgebit,destination=/var/lib/edgebit" \
  -e "EDGEBIT_ID=YOUR_DEPLOYMENT_TOKEN" \
  -e "EDGEBIT_URL=https://YOUR_ORG.edgebit.io" \
  edgebit-agent:latest --hostname "$(hostname)"
```

# Kubernetes based deployment

The agent can be deployed on the Kubernetes as a privileged pod running as a DaemonSet:

1. Edit [config.yaml](dist/kube/config.yaml) to put configure the EdgeBit URL and your EdgeBit ID (Deployment Token).

2. Apply [config.yaml](dist/kube/config.yaml):
```
kubectl apply -f config.yaml
```

3. Apply [daemonset.yaml](dist/kube/daemonset.yaml) to deploy the Agent:
```
kubectl apply -f daemonset.yaml
```
