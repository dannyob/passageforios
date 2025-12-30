module github.com/mssun/passforios/sshage/mobile

go 1.21

require github.com/mssun/passforios/sshage v0.0.0

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

replace github.com/mssun/passforios/sshage => ../..
