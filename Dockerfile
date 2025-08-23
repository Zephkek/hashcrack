# syntax=docker/dockerfile:1
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go mod tidy
ARG GOAMD64=v3
ENV GOAMD64=${GOAMD64}
RUN CGO_ENABLED=0 GOAMD64=${GOAMD64} \
	go build -ldflags="-s -w" -trimpath -o /out/hashcrack ./cmd/hashcrack

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /out/hashcrack /usr/local/bin/hashcrack
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hashcrack"]
CMD ["web", "--addr", ":8080"]
