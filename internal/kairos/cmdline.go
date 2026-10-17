package kairos

import (
	"strings"

	"github.com/google/shlex"
)

// cmdlineTokens splits a kernel command line the way the agent does, with
// shlex and its error ignored, which drops what follows an unbalanced
// quote.
func cmdlineTokens(cmdline string) []string {
	tokens, _ := shlex.Split(cmdline)
	return tokens
}

// AgentDebug tells whether a kernel command line turns on kairos-agent's
// debug log, which prints the whole configuration: a bare or valued debug,
// the same as a kairos.config= or cos.setup= stanza, or rd.kairos.debug,
// which the agent matches as a substring.
func AgentDebug(cmdline string) bool {
	if strings.Contains(cmdline, "rd.kairos.debug") {
		return true
	}
	for _, f := range cmdlineTokens(cmdline) {
		s, stanza := strings.CutPrefix(f, "kairos.config=")
		if !stanza {
			// cos.setup= without a value is a config URL.
			if s, stanza = strings.CutPrefix(f, "cos.setup="); stanza && s == "debug" {
				continue
			}
		}
		if v, ok := strings.CutPrefix(s, "debug="); s == "debug" || ok && v != "false" {
			return true
		}
	}
	return false
}
