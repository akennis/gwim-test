# gwim-test

A minimal consumer of the [gwim](https://github.com/akennis/gwim) package, used to verify that gwim integrates correctly as a Go module dependency.

## What this is

`gwim-test` is a single-file Go program that stands up a minimal HTTPS server on Windows with integrated Windows Authentication (Kerberos or NTLM via SSPI) and optional LDAP group lookup. It exercises the core gwim API surface — `NewSSPIHandler`, `NewLdapGroupProvider`, `GetWin32Cert`, `User`, and `UserGroups` — in a real consumer module context.

This repository exists to catch integration regressions (import paths, API breakage, transitive dependency issues) that unit tests within the gwim package itself cannot detect.

## Usage

```
go run min-win-server.go [flags]

Flags:
  -server-addr string          Address[:port] to listen on (default "localhost:8443")
  -cert-subject string         Subject of the Windows certificate to use (default "localhost")
  -cert-from-current-user      Load certificate from CurrentUser store instead of LocalMachine
  -use-ntlm                    Use NTLM instead of Kerberos (required for localhost/non-domain)
  -ldap-address string         LDAP server address (optional)
  -ldap-users-dn string        DN for users in LDAP (optional)
  -ldap-service-account-spn    SPN of the LDAP service account (optional)
```

When LDAP flags are omitted, the server runs with SSPI authentication only and skips group enrichment.

## Requirements

- Windows (SSPI is Windows-only)
- A TLS certificate installed in the Windows certificate store matching `-cert-subject`
- For Kerberos: a domain-joined machine and a valid SPN

## Further information

See the main [gwim](https://github.com/akennis/gwim) repository for full documentation, the complete API reference, and additional examples.

## License

This project is licensed under the BSD 3-Clause License — see the [LICENSE](LICENSE) file for details.
