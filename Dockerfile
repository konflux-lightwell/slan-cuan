FROM registry.access.redhat.com/ubi10/ubi:latest AS builder

# Install the builder dependencies
RUN dnf -y install \
    --setopt=install_weak_deps=false \
    --setopt=tsflags=nodocs \
    --setopt=deltarpm=0 \
    --allowerasing \
    --skip-broken \
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

# Install dependencies
RUN echo "${RH_IT_CERT}" | base64 -d > /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem \
    && update-ca-trust \
    && microdnf install -y \
        python3.12-pip \
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
