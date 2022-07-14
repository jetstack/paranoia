# Paranoia

Who do you trust?

Paranoia is a tool to analyse and export trust bundles (like "ca certificates") from container images.

It can be used to inspect and validate the certificates within your container images, as can be seen in our
GitHub action [here](action.yml).

Paranoia is built by [Jetstack](https://jetstack.io) and made available under the Apache 2.0 license, see [LICENSE.txt](LICENSE.txt).

## Usage

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
````

### Validate

Compares found certificates against a given configuration file (`.paranoia.yaml` by default) and reports on any
conflicts.

**Flags:**

`--permissive`: Enables permissive mode, allowing all certificates unless explicitly forbidden. When not
enabled `validate` defaults to `strict` mode where all certificates are forbidden unless explicitly allowed.

`--warn`: Forces the process to end with exit code 0 regardless of whether conflicts are found. Output remains the same.

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
$ paranoid export alpine:latest
File Location                      Owner                                                        Not Before            Not After             SHA-256                                                           
etc/ssl/certs/ca-certificates.crt  ACCVRAIZ1                                                    2011-05-05T09:37:37Z  2030-12-31T09:37:37Z  9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113  
etc/ssl/certs/ca-certificates.crt                                                               2008-10-29T15:59:56Z  2030-01-01T00:00:00Z  ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa  
etc/ssl/certs/ca-certificates.crt  AC RAIZ FNMT-RCM SERVIDORES SEGUROS                          2018-12-20T09:37:33Z  2043-12-20T09:37:33Z  554153b13d2cf9ddb753bfbe1a4e0ae08d0aa4187058fe60a2b862b2e4b87bcb  
...
etc/ssl/certs/ca-certificates.crt  vTrus ECC Root CA                                            2018-07-31T07:26:44Z  2043-07-31T07:26:44Z  30fbba2c32238e2a98547af97931e550428b9b3f1c8eeb6633dcfa86c5b27dd3  
etc/ssl/certs/ca-certificates.crt  vTrus Root CA                                                2018-07-31T07:24:05Z  2043-07-31T07:24:05Z  8a71de6559336f426c26e53880d00d88a18da4c6a91f0dcb6194e206c5c96387  
Found 132 certificates
```

### Global flags

`- --output`: Allows specification of the output mode. Supports `pretty` and `json`. Defaults to `pretty`.
