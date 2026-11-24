//go:build linux

package x02

import (
	"fmt"

	"github.com/marcgauthier/memarmor"
	"github.com/marcgauthier/memarmor/internal/thirdparty/xsys/linux"
)

func POC() {
	key := memarmor.NewEnclaveRandom(32)

	var oldLimit linux.Rlimit
	zeroLimit := linux.Rlimit{Cur: 0, Max: oldLimit.Max}
	if err := linux.Prlimit(0, linux.RlimitMemlock, &zeroLimit, &oldLimit); err != nil {
		panic(fmt.Errorf("error lowering memlock rlimit: %s", err))
	}

	keyBytes, err := key.Open()
	if err != nil {
		panic(err)
	}
	defer keyBytes.Destroy()
}
