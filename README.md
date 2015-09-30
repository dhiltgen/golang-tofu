# golang-tofu
Simple golang lib for TLS [Trust On First Use](https://en.wikipedia.org/wiki/Trust_on_first_use)
which can be used to establish trust for self-signed server certificates.

First, call `GetFingerprints` to retrieve the server certificate details.
The user should then perform validation through some side-band channel.
Once the user has verified the certificate fingerprint, the fingerprint
can be stored, and used for subsequent connections to the server.

See [example/main.go](example/main.go) for an example using this library.
