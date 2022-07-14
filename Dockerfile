FROM golang:1.18-alpine as builder
WORKDIR /go/src/github.com/jetstack/paranoia

# Download necessary Go modules
COPY ./go.mod ./
COPY ./go.sum ./
RUN go mod download

# Copy the files into the container
COPY ./cmd cmd
COPY ./pkg pkg
COPY ./main.go .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o paranoia .

# Build tiny container
FROM alpine:latest
COPY --from=builder /go/src/github.com/jetstack/paranoia/paranoia .
ENTRYPOINT ["paranoia"]
