package kairos

import "github.com/cockroachdb/errors"

// ErrBadConfig marks a cloud-config the operator has to fix.
var ErrBadConfig = errors.New("--cloud-config is not a cloud-config")
