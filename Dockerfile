FROM golang:1.18-alpine as builder
WORKDIR /go/src/github.com/jetstack/paranoia

# Download necessary Go modules
COPY ./go.mod ./
COPY ./go.sum ./
RUN go mod download

# Copy the files into the container
COPY main.go main.go
COPY ./cmd cmd
COPY ./internal internal

# Setup tmp directory
RUN mkdir /new_tmp

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o paranoia .

# Build tiny container
FROM scratch
COPY --from=builder /new_tmp /tmp
COPY --from=builder /go/src/github.com/jetstack/paranoia/paranoia .
ADD https://cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem /etc/ssl/certs/DigiCertGlobalRootCA.crt
ENTRYPOINT ["/paranoia"]
