package backup

import (
	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
	"path/filepath"
	"runtime"
	"testing"
)

func TestServerCannotDecryptCapsules(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	guardtest.NoDecryptOutside(t, root, map[string][]string{"cmd/kynotes-server/backup.go": {"restoreCapsule"}})
}
