package daemon

import (
	"database/sql"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func plantStoreTagAnchor(*testing.T, *sql.DB) {}

func withoutTagAnchor(rows []cookie.EncryptedRow) []cookie.EncryptedRow { return rows }
