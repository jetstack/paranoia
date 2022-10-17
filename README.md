# Paranoia

_Who do you trust?_

Paranoia is a tool to analyse and export trust bundles (e.g., "ca-certificates") from container images. These certificates identify the certificate authorites that your container trusts when establishing TLS connections. The design of TLS is that any certificate authority that your container trusts can issue a certificate for any domain. This means that a malicious or compromised certificate authority could issue a certificate to impersonate any other service, including your internal infrastructure.

Paranoia can be used to inspect and validate the certificates within your container images. This gives you visibility into which certificate authorities your container images are trusting; allows you to forbid or require certificates at build-time in CI; and help you decide _who to trust_ in your container images.

Paranoia is built by [Jetstack](https://jetstack.io) and made available under the Apache 2.0 license, see [LICENSE.txt](LICENSE.txt).

## Limitations

Paranoia will detect certificate authorities in most cases, and is especially useful at finding accidental inclusion or for conducting a certificate authority inventory. However there are some limitations to bear in mind while using Paranoia:
- Paranoia only functions on container images, not running containers. Anything added into the container at runtime is not seen.
- If a certificate is found, that doesn’t guarantee that the container will trust it as a certificate authority. It could, for example, be an unused leftover file.
- It’s possible for an attacker to ‘hide’ a certificate authority from Paranoia (e.g., by encoding it in a format Paranoia doesn’t understand). In general Paranoia isn’t designed to defend against an adversary with supply chain write access intentionally sneaking obfuscated certificate authorities into container images.

## Command Line Usage

### Inspect

Checks found certificates and reports on whether they're valid, expired, due to expire in the next 6 months or are on
[Mozilla's Removed CA Certificate Report](https://ccadb-public.secure.force.com/mozilla/RemovedCACertificateReportCSVFormat).

```shell
$ paranoia inspect alpine:latest
Certificate CN=Hellenic Academic and Research Institutions RootCA 2011,O=Hellenic Academic and Research Institutions Cert. Authority,C=GR
┗ 🚨 removed from Mozilla trust store, no reason given
Certificate CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL
┗ ⚠️️ expires soon ( expires on 2022-12-08T11:10:28Z, 20 weeks 6 days until expiry)
Found 132 certificates total, of which 2 had issues
```

### Validate

Compares found certificates against a given configuration file (`.paranoia.yaml` by default) and reports on any
conflicts.

**Flags:**

`--permissive`: Enables permissive mode, allowing all certificates unless explicitly forbidden. When not
enabled `validate` defaults to `strict` mode where all certificates are forbidden unless explicitly allowed.

`--quiet`: Forces the process to end with exit code 0 regardless of whether conflicts are found. Output remains the same.

`-c --config`: Takes a file path and allows the use of a specified config file rather than the default, `.paranoia.yaml`.

Example config:
```yaml
version: "1"
allow:
  - fingerprints:
      sha256: 30FBBA2C32238E2A98547AF97931E550428B9B3F1C8EEB6633DCFA86C5B27DD3
    comment: "A certificate we're okay with but don't explicitly need"
forbid:
  - fingerprints:
      sha256: 4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161
    comment: "A certificate we definitely don't want"
require:
  - fingerprints:
      sha1: a7c36ea226e1adc60c4aa7866b79ed9e7831103c
    comment: "A certificate that must be present"
```

```shell
$ paranoia validate some-image:latest --config some_config.yaml
Validating certificates with 1 allowed, 1 forbidden, and 1 required certificates, in strict mode
Scanned 3 certificates in image some-image:latest, found issues.
Certificate with SHA256 fingerprint 4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161 in location etc/ssl/certs/ca-certificates.crt was forbidden Comment: A certificate we definitely don't want 
Certificate with SHA256 fingerprint 30FBBA2C32238E2A98547AF97931E550428B9B3F1C8EEB6633DCFA86C5B27DD3 in location etc/ssl/certs/ca-certificates.crt was not allowed
Certificate with SHA1 a7c36ea226e1adc60c4aa7866b79ed9e7831103c was required, but was not found Comment: A certificate that must be present
exit status 1
```
**Note:** Comments on allowed certificate fingerprints will never be displayed in the output as we don't report on
allowances. However, they can be very helpful for anyone who needs to maintain the file.

### Export

Outputs data on all found certificates, including the file location, owner, valid from and valid to dates and the SHA256
fingerprint (useful for populating a config file for use with the `validate` command).

```shell
$ paranoia export alpine:latest
File Location                       Subject                                                                                                                                                                        
/etc/ssl/certs/ca-certificates.crt  CN=ACCVRAIZ1,OU=PKIACCV,O=ACCV,C=ES                                                                                                                                            
/etc/ssl/certs/ca-certificates.crt  OU=AC RAIZ FNMT-RCM,O=FNMT-RCM,C=ES                                                                                                                                            
/etc/ssl/certs/ca-certificates.crt  CN=AC RAIZ FNMT-RCM SERVIDORES SEGUROS,OU=Ceres,O=FNMT-RCM,C=ES,2.5.4.97=#130f56415445532d51323832363030344a                                                                   
/etc/ssl/certs/ca-certificates.crt  SERIALNUMBER=G63287510,CN=ANF Secure Server Root CA,OU=ANF CA Raiz,O=ANF Autoridad de Certificacion,C=ES                                                                       
/etc/ssl/certs/ca-certificates.crt  CN=Actalis Authentication Root CA,O=Actalis S.p.A./03358520967,L=Milan,C=IT                                                                                                    
/etc/ssl/certs/ca-certificates.crt  CN=AffirmTrust Commercial,O=AffirmTrust,C=US                                                                                                                                   
/etc/ssl/certs/ca-certificates.crt  CN=AffirmTrust Networking,O=AffirmTrust,C=US                                                                                                                                   
/etc/ssl/certs/ca-certificates.crt  CN=AffirmTrust Premium,O=AffirmTrust,C=US                                                                                                                                      
/etc/ssl/certs/ca-certificates.crt  CN=AffirmTrust Premium ECC,O=AffirmTrust,C=US
…
/etc/ssl/certs/ca-certificates.crt  CN=vTrus ECC Root CA,O=iTrusChina Co.\,Ltd.,C=CN                                                                                                                               
/etc/ssl/certs/ca-certificates.crt  CN=vTrus Root CA,O=iTrusChina Co.\,Ltd.,C=CN                                                                                                                                   
Found 140 certificates
```

### Global flags

`-o --output`: Allows specification of the output mode. Supports `pretty`, `wide`, and `json`. Defaults to `pretty`.

`--platform`: Specifies the platform in the form `os/arch[/variant][:osversion]` (e.g. `linux/amd64`)

## CI Usage

The functionality of Paranoia is well suited to running in CI pipelines, either producing reports on a schedule or
as a check before or after the release of a new container image.

Below are some examples:

### GitHub Actions

Paranoia is used on itself after container image build to confirm that it only contains the certificates that we expect.
The full workflow can be found [here](.github/workflows/publish.yaml).

In it we use our [paranoia action](action.yml) to run the validation, using the `file://` prefix to read the container
image from a local file, as opposed to pulling it from a container registry:

```yaml
...
- name: Build and export to Docker
  uses: docker/build-push-action@v3
  with:
    context: .
    load: true
    cache-from: type=gha
    cache-to: type=gha,mode=max
    outputs: type=docker,dest=${{ env.CONTAINER_TAR }}

- name: "Run Paranoia container"
  uses: ./
  with:
    action: validate
    target_tar: file://${{ env.CONTAINER_TAR }}
...
```
