package core

import (
	"errors"
	"fmt"
)

// ErrMemoryProtection indicates that a requested mapping protection was unavailable.
var ErrMemoryProtection = errors.New("<memarmor::core> required memory protection unavailable")

// MemoryProtectionRequirements lists the required protections for all guarded
// mappings, including MemArmor's internal allocations.
type MemoryProtectionRequirements struct {
	CoreDumpExclusion bool
	ForkWipe          bool
}

// MemoryProtectionStatus records the results for one guarded mapping. A nil
// field means that the corresponding protection was applied at allocation.
type MemoryProtectionStatus struct {
	CoreDumpExclusion error
	ForkWipe          error
}

// memoryProtectionRequirements is changed only with exclusive session access.
var memoryProtectionRequirements MemoryProtectionRequirements

func (r MemoryProtectionRequirements) check(status MemoryProtectionStatus) error {
	var err error
	if r.CoreDumpExclusion && status.CoreDumpExclusion != nil {
		err = fmt.Errorf("%w: core dump exclusion: %w", ErrMemoryProtection, status.CoreDumpExclusion)
	}
	if r.ForkWipe && status.ForkWipe != nil {
		err = errors.Join(err, fmt.Errorf("%w: fork wipe: %w", ErrMemoryProtection, status.ForkWipe))
	}
	return err
}

// RequireMemoryProtection sets a process-wide policy. The zero value restores
// best-effort protection. Existing buffers must meet the new policy. When
// there are no live buffers, a temporary allocation verifies the policy.
// A failure leaves the previous policy in effect.
func RequireMemoryProtection(required MemoryProtectionRequirements) error {
	sessionMu.Lock()
	defer finishSessionTransition()

	if required == (MemoryProtectionRequirements{}) {
		memoryProtectionRequirements = required
		return nil
	}
	hasLive := false
	for _, b := range buffers.copy() {
		if b.Alive() {
			hasLive = true
			// The allocation status is immutable after registration.
			if err := required.check(b.protection); err != nil {
				return err
			}
		}
	}
	if !hasLive {
		probe, err := newBufferWithProtection(1, required)
		if err != nil {
			return err
		}
		if err := probe.release(); err != nil {
			return err
		}
	}
	memoryProtectionRequirements = required
	return nil
}
