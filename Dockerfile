FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS pqbuild
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY scripts/build-pqwasm.sh scripts/
RUN bash scripts/build-pqwasm.sh

FROM node:26.13.1-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web .
# teamKeys.test.ts type-checks against the shared protocol vectors at ../../testdata.
COPY testdata/protocol /src/testdata/protocol
COPY --from=pqbuild /src/web/public/assets/pq ./public/assets/pq
# The Go build stage above owns WASM generation.
RUN node src/ky-ui/check-vendor.mjs && npx tsc --noEmit && npx vite build

FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
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
