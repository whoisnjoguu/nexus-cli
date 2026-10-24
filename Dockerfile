# syntax=docker/dockerfile:1
#
# nexus-cli sidecar image. The release workflow builds it with goreleaser (dockers_v2) from the
# prebuilt linux binaries; build it locally with `make docker`.
#
# The build context must contain <os>/<arch>/nexus-cli for each target platform.

FROM --platform=$BUILDPLATFORM busybox:1.37 AS prep
RUN mkdir -p /nexus

FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM

COPY --from=prep --chown=65532:65532 /nexus /home/nonroot/.nexus
COPY --chmod=0755 $TARGETPLATFORM/nexus-cli /usr/local/bin/nexus-cli

ENV NEXUS_HOME=/home/nonroot/.nexus \
    NEXUS_KEY_BACKEND=file \
    NEXUS_NOTIFY=off
WORKDIR /home/nonroot
VOLUME ["/home/nonroot/.nexus"]
EXPOSE 8075

ENTRYPOINT ["/usr/local/bin/nexus-cli"]
CMD ["dev", "--listen", "0.0.0.0:8075"]
