FROM node:24.18.1-bookworm-slim@sha256:235600a8101ab264e117b1768e925532262668dc9b581ef1dd7d96ced463b8e7 AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web .
# teamKeys.test.ts type-checks against the shared protocol vectors at ../../testdata.
COPY testdata/protocol /src/testdata/protocol
RUN npm run build

FROM golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS build
WORKDIR /src
RUN mkdir -p /data /tmp && chown 65532:65532 /data /tmp
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/dist /src/internal/web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION}" -o /kynotes-server ./cmd/kynotes-server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /kynotes-server /kynotes-server
COPY --from=build --chown=nonroot:nonroot /data /data
COPY --from=build --chown=nonroot:nonroot /tmp /tmp
USER nonroot
EXPOSE 8080
VOLUME /data
HEALTHCHECK CMD ["/kynotes-server","healthcheck"]
ENTRYPOINT ["/kynotes-server"]
