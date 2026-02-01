//go:build db_no_sqlite

package database

// IsSqliteBusyError 在禁用 sqlite 时恒返回 false
func IsSqliteBusyError(err error) bool {
	return false
}
