package core

import (
	"errors"
	"testing"
)

func TestRequireMemoryProtection(t *testing.T) {
	Purge()
	t.Cleanup(func() {
		if err := RequireMemoryProtection(MemoryProtectionRequirements{}); err != nil {
			t.Error(err)
		}
	})

	// Exercise the startup probe, when no live mappings exist.
	req := MemoryProtectionRequirements{CoreDumpExclusion: true, ForkWipe: true}
	strictErr := RequireMemoryProtection(req)

	b, err := NewBuffer(32)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	status := b.MemoryProtection()
	if status.CoreDumpExclusion != nil || status.ForkWipe != nil {
		if !errors.Is(strictErr, ErrMemoryProtection) {
			t.Fatalf("strict mode should reject missing protections: %v", strictErr)
		}
		if err := RequireMemoryProtection(req); !errors.Is(err, ErrMemoryProtection) {
			t.Fatalf("strict mode accepted an existing insufficient mapping: %v", err)
		}
	} else if strictErr != nil {
		t.Fatalf("could not require available protections: %v", strictErr)
	}

	b.Destroy()
	status = b.MemoryProtection()
	if !errors.Is(status.CoreDumpExclusion, ErrBufferExpired) || !errors.Is(status.ForkWipe, ErrBufferExpired) {
		t.Fatalf("destroyed mapping reported protection: %+v", status)
	}
}
