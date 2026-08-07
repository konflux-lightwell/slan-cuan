FROM registry.access.redhat.com/ubi10/ubi:10.2 AS builder

# Install the builder dependencies
RUN dnf -y install \
    --setopt=install_weak_deps=false \
    --setopt=tsflags=nodocs \
    --setopt=deltarpm=0 \
    --allowerasing \
    python3.12-pip \
    python3.12-devel \
    git \
    gcc \
    make \
    && dnf clean all \
    && mkdir -p /export/wheels

# Copy the project source code
COPY . /src/
WORKDIR /src

# Generate the wheels
RUN pip3.12 wheel --wheel-dir=/export/wheels .


# Build the final image using task-runner which includes oras and other Tekton tooling
FROM quay.io/konflux-ci/task-runner:1.5.0

LABEL \
    name="slan-cuan" \
    maintainer="Lightwell Developers" \
    licence="Apache-2.0"

# Copy the wheels from the builder stage
COPY --from=builder /export/ /

USER 0

ARG RH_IT_CERT
ARG KUBECTL_VERSION=1.27.2
ARG INTERNAL_REQUESTS_SCRIPT_URL=https://raw.githubusercontent.com/konflux-ci/release-service-utils/refs/heads/main/utils/internal-request
ARG WAIT_INTERNAL_REQUEST_SCRIPT_URL=https://raw.githubusercontent.com/konflux-ci/release-service-utils/refs/heads/main/utils/wait-for-internal-request

# Install dependencies
RUN echo "${RH_IT_CERT}" | base64 -d > /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem \
    && update-ca-trust \
    && microdnf install -y \
        python3.12-pip \
        jq \
    # For internal-requests on Konflux (required for direct signing)
    && curl -L https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl -o /usr/bin/kubectl \
    && curl -L ${INTERNAL_REQUESTS_SCRIPT_URL} -o /usr/bin/internal-request \
    && curl -L ${WAIT_INTERNAL_REQUEST_SCRIPT_URL} -o /usr/bin/wait-for-internal-request \
    && chmod +x /usr/bin/{kubectl,internal-request,wait-for-internal-request} \
    # for CVEs in base image
    && microdnf update -y \
    && microdnf clean all \
    && pip3.12 install --no-cache-dir --no-deps /wheels/*.whl \
    && rm -rf /wheels

# Set the internal certificates
ENV REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
ENV SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt

# Hack: We need to install python-qpid-proton==0.38.0 to avoid SLL Errors on AMPQ
RUN microdnf install -y gcc gcc-c++ make cmake python3-devel openssl-devel cyrus-sasl-devel \
    && python3 -m pip install --upgrade pip \
    && pip3 install python-qpid-proton==0.38.0

# Embed Tekton Task definitions
COPY tekton/tasks/ /tekton/tasks/

# Run the CLI
ENTRYPOINT ["slan-cuan", "--verbose" ]
