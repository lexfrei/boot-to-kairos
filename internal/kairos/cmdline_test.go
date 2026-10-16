package kairos

import "testing"

func TestAgentDebug(t *testing.T) {
	for cmdline, want := range map[string]bool{
		"BOOT_IMAGE=/vmlinuz root=/dev/vda1 quiet debug\n": true,
		"quiet debug=true":                    true,
		"debug=1 ro":                          true,
		"debug=false":                         false,
		`debug="false"`:                       false,
		`quiet "debug"`:                       true,
		"rd.immucore.debug":                   false,
		"rd.kairos.debug":                     true,
		"kairos.config=debug":                 true,
		"kairos.config=debug=true":            true,
		"kairos.config=debug=false":           false,
		"cos.setup=debug=true":                true,
		"cos.setup=debug":                     false,
		"kairos.config=install.auto=true":     false,
		"nodebug systemd.debug-shell=1 quiet": false,
		"":                                    false,
	} {
		if got := AgentDebug(cmdline); got != want {
			t.Errorf("%q: debug = %v", cmdline, got)
		}
	}
}
