# Paranoia

_Who do you trust?_

Paranoia is a tool to analyse and export trust bundles (e.g., "ca-certificates") from container images.
These certificates identify the certificate authorities that your container trusts when establishing TLS connections.
The design of TLS is that any certificate authority that your container trusts can issue a certificate for any domain.
This means that a malicious or compromised certificate authority could issue a certificate to impersonate any other service, including your internal infrastructure.

Paranoia can be used to inspect and validate the certificates within your container images.
This gives you visibility into which certificate authorities your container images are trusting; allows you to forbid or require certificates at build-time in CI; and help you decide _who to trust_ in your container images.

Paranoia is built by [Jetstack](https://jetstack.io) and made available under the Apache 2.0 license, see [LICENSE.txt](LICENSE.txt).

## Installation

### Homebrew

On macOS and Linux, if you have [Homebrew](https://brew.sh) you can install Paranoia with:

```shell
brew install jetstack/jetstack/paranoia
```

This will also install man pages and shell completion.

### Binaries

Binaries for common platforms and architectures are provided on the [releases](https://github.com/jetstack/paranoia/releases/latest).
Man pages are also attached to the release.
You can generate shell completion from Paranoia itself with `paranoia completion`.

### Go Install

If you have [Go](https://go.dev/) installed you can install Paranoia using Go directly.

```shell
go install github.com/jetstack/paranoia@latest
```

## Examples

Paranoia can be used to list out the certificates in a container image:

```shell
$ paranoia export alpine:latest
File Location                       Subject
/etc/ssl/certs/ca-certificates.crt  CN=ACCVRAIZ1,OU=PKIACCV,O=ACCV,C=ES
/etc/ssl/certs/ca-certificates.crt  OU=AC RAIZ FNMT-RCM,O=FNMT-RCM,C=ES
/etc/ssl/certs/ca-certificates.crt  CN=AC RAIZ FNMT-RCM SERVIDORES SEGUROS,OU=Ceres,O=FNMT-RCM,C=ES,2.5.4.97=#130f56415445532d51323832363030344a
…
/etc/ssl/certs/ca-certificates.crt  CN=vTrus ECC Root CA,O=iTrusChina Co.\,Ltd.,C=CN
/etc/ssl/certs/ca-certificates.crt  CN=vTrus Root CA,O=iTrusChina Co.\,Ltd.,C=CN
Found 140 certificates
```

Export them for further audit:

```shell
paranoia export --output json python:3 | jq '.certificates[].fingerprintSHA256' | head -n 5

"ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99"
"6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177"
"16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb"
"73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c"
"d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"
```

Detect internal certificates left over from internal testing:

```shell
cat << EOF > .paranoia.yaml
version: "1"
forbid:
  - comment: "An internal-only cert"
    fingerprints:
      sha256: bd40be0eccfce513ab318882f03962e4e2ec3799b51392e82805d9249e426d28
EOF
paranoia validate my-image
```

Find certificates inside binaries:

```shell
paranoia export -o json consul:latest | jq '.certificates[] | select(.fileLocation == "/bin/consul")'
{
  "fileLocation": "/bin/consul",
  "owner": "CN=Circonus Certificate Authority,OU=Circonus,O=Circonus\\, Inc.,L=Columbia,ST=Maryland,C=US,1.2.840.113549.1.9.1=#0c0f636140636972636f6e75732e6e6574",
  "parser": "pem",
  "signature": "01C1B65D790706D2CAAD1D30406911D41884789A9D4FEBBCE31EE7B7628019A8C7B6643C46C1FDB684B18272B33880DAB68EB51C5546D731B9948C8A3D918890EC2F1CC8A751FAD1786BF2599FEEA17A63EB1997B577E8A65B9F67B368EA11B6C425F5D86A10C7BCCE02FBEA9F5867913AF409749A08A27D3B5EC8D8E332E216",
  "notBefore": "2009-12-23T19:17:06Z",
  "notAfter": "2019-12-21T19:17:06Z",
  "fingerprintSHA1": "063ff657e055b0036d794cda892c85417c07739a",
  "fingerprintSHA256": "0c97e0898343c5b1973c6568a15c8c853dd663d363020071e34f789859ece19f"
}
```

## Limitations

Paranoia will detect certificate authorities in most cases, and is especially useful at finding accidental inclusion or for conducting a certificate authority inventory.
However, there are some limitations to bear in mind while using Paranoia:

- Paranoia only functions on container images, not running containers.
  Anything added into the container at runtime is not seen.
- If a certificate is found, that doesn’t guarantee that the container will trust it as a certificate authority.
  It could, for example, be an unused leftover file.
- It’s possible for an attacker to ‘hide’ a certificate authority from Paranoia (e.g., by encoding it in a format Paranoia doesn’t understand).
  In general Paranoia isn’t designed to defend against an adversary with supply chain write access intentionally sneaking obfuscated certificate authorities into container images.

## Usage

The usage documentation for Paranoia is included in the help text.
Invoke a command with `--help` for usage instructions, or see the manual pages.

## Controller Mode

Paranoia can be run in a controller mode

### Monitoring

To Monitor Paranoia, running in Controller Mode, You can use the example grafana dashboard provided in the `monitoring` directory, and to monitor the Go Process, you can import the `Go Process` dashboard from the Grafana Dashboards repository. The Go Process dashboard is available at [Go Processes](https://grafana.com/grafana/dashboards/6671-go-processes/).

### Registry Authentication

### Google Authentication

Paranoia Authenticates to Google Container Registry using `https://github.com/GoogleCloudPlatform/docker-credential-gcr` helper.

The most secure and recommended way to authenticate with GCR Credential Helper is to use Workload Identity. This allows you to use the identity of a GKE workload to authenticate with GCR without needing to manage service account keys.

Alternatively, you can use a service account key file. To do this, you need to set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the path of the service account key file, and ensure it is mounted into the container at the same path.

#### Unsupported Registry Authentication

Paranoia does not support authentication to private registries. If you need to authenticate to a private registry, you can mount a docker config file at location `~/.docker/config.json` This file should contain the credentials for the private registry in the standard Docker config format.
