package cli

import (
	"fmt"
	"io"
)

// art is the startup banner, 41 columns wide.
const art = `
  ____  _      ____   _____  _  __ ____  
 / ___|| |    |  _ \ |  ___|| |/ /|  _ \ 
| |    | |    | |_) || |_   | ' / | | | |
| |___ | |___ |  _ < |  _|  | . \ | |_| |
 \____||_____||_| \_\|_|    |_|\_\|____/ `

const bannerWidth = 41

// Banner writes the startup banner to w.
//
// It goes to stderr, never stdout: a banner in a pipeline's input would have to
// be filtered back out by whatever is downstream. Callers suppress it entirely
// in silent and JSON modes, where the reader is a machine.
func Banner(w io.Writer, color bool) {
	cyan, dim, reset := "", "", ""
	if color {
		cyan, dim, reset = "\033[36m", "\033[2m", "\033[0m"
	}
	tag := fmt.Sprintf("%*s", bannerWidth, "CRLF injection scanner  "+Version)
	fmt.Fprintf(w, "%s%s%s\n%s%s%s\n\n", cyan, art, reset, dim, tag, reset)
}
