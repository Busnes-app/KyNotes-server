FROM node:26.12.1-bookworm-slim@sha256:88e480776c6149ff1d098cd304f44bf18057fb5d284a3329b78162d29821e28c AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web .
# teamKeys.test.ts type-checks against the shared protocol vectors at ../../testdata.
COPY testdata/protocol /src/testdata/protocol
RUN npm run build

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS build
WORKDIR /src
RUN mkdir -p /data /tmp && chown 65532:65532 /data /tmp
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/dist /src/internal/web/dist
# Release builds pass the tag's version (X.Y.Z or X.Y.Z.N) and CI passes the commit SHA;
# a build without VERSION reports internal/appversion/VERSION.
ARG VERSION=
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-X github.com/Busnes-app/kynotes-server/internal/appversion.release=${VERSION}" \
    -o /kynotes-server ./cmd/kynotes-server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /kynotes-server /kynotes-server
COPY --from=build --chown=nonroot:nonroot /data /data
COPY --from=build --chown=nonroot:nonroot /tmp /tmp
USER nonroot
EXPOSE 8080
VOLUME /data
HEALTHCHECK CMD ["/kynotes-server","healthcheck"]
ENTRYPOINT ["/kynotes-server"]
