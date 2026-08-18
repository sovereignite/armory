module github.com/sovereignite/keymanager

go 1.26.5

require github.com/sovereignite/tpm v0.0.0

require (
	github.com/google/go-tpm v0.9.8 // indirect
	golang.org/x/sys v0.8.0 // indirect
)

replace github.com/sovereignite/tpm => ../tpm
