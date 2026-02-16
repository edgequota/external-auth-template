FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /auth-server .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /auth-server /auth-server
EXPOSE 8080
ENTRYPOINT ["/auth-server"]
