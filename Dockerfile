FROM registry.access.redhat.com/ubi9/ubi:latest AS builder

ARG RH_IT_CERT

# Install the builder dependencies
RUN dnf -y install \
    --setopt=install_weak_deps=false \
    --setopt=tsflags=nodocs \
    --setopt=deltarpm=0 \
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

# Authenticate in the internal git repository to fetch the dependencies such as novabucks
# and generate the wheels
RUN echo ${RH_IT_CERT} > /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem \
    && update-ca-trust extract \
    &&  pip3.12 wheel --wheel-dir=/export/wheels .


# Build the final image using ubi-minimal to reduce the image size
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL \
    name="slan-cuan" \
    maintainer="Lightwell Developers" \
    licence="Apache-2.0"

# Copy the wheels from the builder stage
COPY --from=builder /export/ /

# Setup RH-IT-Root-CA certificate for RedHat
RUN echo ${RH_IT_CERT} > /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem \
    && update-ca-trust extract \
    # Install dependencies
    && microdnf install -y \
        python3.12-pip \
    # for CVEs in base image
    && microdnf update -y \
    && microdnf clean all \
    && pip3.12 install --no-cache-dir --no-deps /wheels/*.whl \
    && rm -rf /wheels

# Set the internal certificates
ENV REQUESTS_CA_BUNDLE=/etc/pki/tls/cert.pem

# Embed Tekton Task definitions
COPY tekton/tasks/ /tekton/tasks/

# Run the CLI
ENTRYPOINT ["slan-cuan"]
