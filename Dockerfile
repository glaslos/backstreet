# syntax=docker/dockerfile:1.7
FROM golang:1.26.9-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/backstreet ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/backstreet /backstreet
USER nonroot:nonroot
ENTRYPOINT ["/backstreet"]
