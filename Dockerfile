FROM scratch
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/openbao-seal-spire /openbao-seal-spire
ENTRYPOINT ["/openbao-seal-spire"]
