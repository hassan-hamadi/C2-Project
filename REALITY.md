# REALITY transport guide

This guide describes the REALITY transport implemented in the current source tree. Use it only on infrastructure you control or have explicit authorization to test. A decoy hostname belongs to another service; do not treat that hostname as permission to probe, impersonate, or disrupt it.

## What this mode does

REALITY mode changes how a generated agent reaches the Flask service. It does not replace the application's check-in, task, result, or file-transfer protocol.

```text
Generated Go agent
  HTTP request encrypted by the application protocol
       |
       v
  VLESS TCP request for 127.0.0.1:5000
       |
       v
  REALITY-authenticated TLS 1.3 connection using a uTLS preset
       |
       v
Xray REALITY/VLESS inbound on the network edge
       |
       v
Flask server on 127.0.0.1:5000 from Xray's point of view
```

The components have separate jobs:

- **uTLS** constructs the selected ClientHello preset.
- **REALITY** authenticates the client inside the TLS handshake using the server's X25519 public key and short ID.
- **VLESS** asks Xray for a TCP stream to the Flask destination.
- **Xray** terminates REALITY and VLESS and connects to Flask.
- **Flask** continues to process the same encrypted HTTP application messages used by direct transports.

The server in this repository does not install Xray, create an Xray configuration, open firewall ports, issue REALITY credentials, or manage the edge service. Those are operator responsibilities.

## Build fields

Choose **REALITY (uTLS + VLESS)** on the dashboard's Deploy page and provide every field below.

| Dashboard field | Meaning | Validation in this project |
| --- | --- | --- |
| VPS Address | Xray listener address in `host:port` form. | Must be non-empty and contain a port separator. The agent passes it to the TCP dialer. |
| Decoy Domain | REALITY `serverName` and TLS SNI. | Must be a hostname when measured. Build input rejects control characters and excessive length. |
| X25519 Public Key | Public key corresponding to Xray's REALITY private key. | Base64 or base64url input must decode to 32 bytes. |
| Short ID | One short ID accepted by the Xray inbound. | Non-empty hexadecimal input, at most 8 decoded bytes. |
| VLESS UUID | Client identifier accepted by the VLESS inbound. | Canonical UUID text. |
| Browser Profile | Header profile and uTLS fingerprint family. | Mapped as shown below. |
| Locale | `Accept-Language` value in the HTTP header profile. | Non-empty text within the build-input size limit. |

REALITY builds do not use the dashboard's callback URL. The build pipeline fixes the inner URL to `http://127.0.0.1:5000` and encodes the VLESS destination as IPv4 `127.0.0.1`, port `5000`. Configure Xray and the host network so that this destination reaches Flask from the Xray process. Do not expose Flask more broadly than the deployment requires.

## Browser profile mapping

| Profile ID | Dashboard label | uTLS family |
| --- | --- | --- |
| 1 | Chrome / Windows | Chrome auto preset |
| 2 | Chrome / Linux | Chrome auto preset |
| 3 | Firefox / Windows | Firefox auto preset |
| 4 | Firefox / Linux | Firefox auto preset |
| 5 | Safari / macOS | Safari auto preset |

The selected uTLS preset affects the ClientHello. The agent also applies a static browser-inspired HTTP header profile. These layers do not reproduce all behavior of an interactive browser. Go's HTTP transport controls wire details such as header encoding and ordering, and this project has not demonstrated browser indistinguishability by packet-capture comparison.

## Xray-side requirements

Prepare an Xray REALITY/VLESS inbound whose values agree with the build:

1. Listen at the address entered as **VPS Address**.
2. Configure the REALITY private key whose public key was entered in the dashboard.
3. Allow the chosen decoy domain in the REALITY server-name list.
4. Allow the selected short ID.
5. Configure a VLESS client with the selected UUID.
6. Permit the VLESS request to connect to `127.0.0.1:5000` from Xray's network namespace.

Xray configuration schemas can change between releases. Use the documentation for the Xray version you operate and keep its private key out of this repository. The dashboard needs only the public key; a REALITY private key is never required by this project.

## Decoy-domain measurement

The **Measure** action calls the server-side `/api/reality/check-domain` endpoint. The probe:

- accepts a hostname without a scheme, path, or port
- resolves it and rejects the request unless every returned address is public and non-multicast
- connects directly to a validated address while sending the hostname as TLS SNI
- requires TLS 1.3
- retrieves the presented certificate chain
- estimates the TLS Certificate record size and compares it with REALITY's 8,192-byte limit

The estimate includes certificate DER lengths and basic TLS framing. It intentionally excludes certificate-entry extensions, record padding, certificate compression, and changes caused by CDN routing or later certificate rotation. The sizing connection does not validate the certificate chain because its purpose is measurement. A successful result means only that the observed chain fit the local estimate; it does not prove that the domain is suitable for an Xray configuration or that a live REALITY session will work.

The probe is an outbound connection initiated by the Flask host. Keep the operator API protected. Its address validation reduces server-side request-forgery risk, but DNS, routing, and certificate results can still change between measurement and deployment.

## Agent initialization and data flow

At build time, the server validates the supplied public values and maps the selected profile to a uTLS family. Generated source contains XOR-obfuscated configuration strings, a fresh application encryption key, randomized agent routes, and the build's REALITY/VLESS credentials. XOR obfuscation only discourages casual string inspection; anyone with the generated binary should be treated as holding its credentials.

At startup, the agent:

1. decodes the generated configuration
2. decodes the 32-byte X25519 public key, short ID, and 16-byte VLESS UUID
3. constructs a REALITY configuration with the decoy name and uTLS family
4. installs an HTTP transport whose dialer connects to the Xray listener
5. performs the REALITY handshake
6. sends a VLESS version 0 TCP request for `127.0.0.1:5000`
7. consumes and validates the VLESS response header on the first read
8. sends ordinary application HTTP requests through the resulting stream

HTTP keep-alive lets Go reuse a stream when the connection remains healthy. Each application message is still protected by the project's AES-256-GCM envelope and agent authentication checks.

## Failure behavior

The connection fails when the TCP dial, ClientHello construction, X25519 exchange, TLS handshake, REALITY certificate authentication, VLESS request, or VLESS response validation fails. If Xray rejects the REALITY credentials and the connection presents the real decoy certificate, the client validates that certificate against the configured decoy name and then returns a REALITY authentication error instead of using the decoy connection.

The agent does not print REALITY handshake material or connection diagnostics. A failed check-in remains silent and is retried after the configured jitter interval. Troubleshoot from controlled server and Xray logs, and do not enable logs that disclose keys or full credentials.

## Troubleshooting

**TCP connection fails**

- Confirm DNS or IP routing to the VPS address and that its port is open.
- Confirm Xray is listening on the same interface and port.

**REALITY credentials are rejected**

- Regenerate the build after checking the public key, decoy domain, short ID, and Xray `serverNames` values.
- Confirm the dashboard received the public key, never the private key.
- Confirm the selected short ID is enabled on the inbound.

**VLESS or first HTTP read fails**

- Confirm the UUID exists on the VLESS inbound.
- Confirm Xray permits a TCP request to IPv4 `127.0.0.1:5000`.
- Confirm Flask is reachable at that address from Xray's network namespace.
- Check for an unexpected VLESS flow, transport, multiplexing, or proxy layer. This client implements the focused TCP path described here.

**The decoy measurement fails**

- Enter only a hostname.
- Use a domain that resolves exclusively to public addresses from the Flask host.
- Confirm the site supports TLS 1.3 and completes within the probe's ten-second deadline.
- Treat a size warning as a reason to choose a different authorized configuration and validate it live.

**The build succeeds but no agent appears**

- Verify Xray first, then Flask reachability, then that the build credentials match the active inbound.
- Remember that failed agent check-ins are intentionally silent.
- Preserve `server/c2.db`; it holds the build key and randomized agent route mapping needed to decrypt and route check-ins.

## Verification status and limitations

Automated Go tests cover REALITY certificate-authentication paths, configuration lookup, VLESS request framing, response-header parsing, unsupported response versions, HTTP-over-stream behavior, and connection reuse. Python build tests compile generated REALITY agents and verify generated transport configuration. Local generated-agent integration tests cover direct HTTP and pinned HTTPS.

A live end-to-end agent-to-Xray-to-Flask REALITY session has not been recorded in this repository. Live compatibility, behavior with a particular Xray release, decoy behavior, and packet-level similarity therefore remain unverified. Validate the complete path in an isolated authorized environment before relying on it.

Current protocol limitations include:

- TCP only
- IPv4 inner destination fixed to `127.0.0.1:5000`
- VLESS version 0 with no request addons
- no UDP
- no multiplexing
- no configurable VLESS flow
- no Xray installation or configuration management
- no claim of exact browser equivalence

## Source and licensing

The focused REALITY handshake in `agent/funcs/reality/reality.go` is adapted from xray-core and remains subject to the Mozilla Public License 2.0. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for the source reference and notice.
