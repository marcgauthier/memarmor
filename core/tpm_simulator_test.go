package core

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/marcgauthier/memarmor/internal/tpm/tpm2"
	"github.com/marcgauthier/memarmor/internal/tpm/tpm2/transport"
)

// Run this against a disposable swtpm instance. The test extends PCR 16.
func TestTPMSimulatorSealPolicy(t *testing.T) {
	socket := os.Getenv("MEMARMOR_SWTPM_SOCKET")
	if socket == "" {
		t.Skip("set MEMARMOR_SWTPM_SOCKET to a disposable swtpm socket")
	}
	device, err := transport.OpenWithTimeout(func() (io.ReadWriteCloser, error) {
		return net.DialTimeout("unix", socket, 5*time.Second)
	}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	sessionMu.RLock()
	defer sessionMu.RUnlock()
	secret := bytes.Repeat([]byte("x"), 32)
	for _, pcrs := range [][]int{nil, {16}} {
		blob, err := sealWithTPM(device, secret, pcrs)
		if err != nil {
			t.Fatalf("seal using PCRs %v: %v", pcrs, err)
		}
		out := make([]byte, len(secret))
		if err := unsealWithTPM(device, blob, out); err != nil {
			t.Fatalf("unseal using PCRs %v: %v", pcrs, err)
		}
		if !bytes.Equal(out, secret) {
			t.Fatalf("incorrect session key using PCRs %v", pcrs)
		}
		if len(pcrs) > 0 {
			_, err := (tpm2.PCRExtend{
				PCRHandle: tpm2.TPMHandle(16),
				Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{
					{HashAlg: tpm2.TPMAlgSHA256, Digest: make([]byte, 32)},
				}},
			}).Execute(device)
			if err != nil {
				t.Fatal(err)
			}
			if err := unsealWithTPM(device, blob, out); err == nil {
				t.Fatal("PCR-bound seal accepted changed measurements")
			}
		}
	}
}
