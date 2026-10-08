// Command clrfkd-lab is a deliberately vulnerable HTTP server for verifying
// the scanner against known-good and known-bad behaviour.
//
// It is written at the socket level on purpose. net/http refuses to write a
// header value containing CR or LF, which is exactly the defect being
// reproduced, so a realistic vulnerable target cannot be built on top of it.
//
// Never expose this on a network you do not control.
//
// Each route takes its tainted value from the "next" query parameter when one
// is present, and from the request path otherwise. That is how a real
// application behaves: it reads one named parameter, not the whole request
// target. It also means a scanner has to place its payload in the right
// parameter to reach the sink, rather than anywhere in the URL.
//
// Routes:
//
//	/hdr    copies the value into a Location header verbatim
//	        (vulnerable: header injection, and response splitting)
//	/cookie copies it into a Set-Cookie header verbatim (vulnerable)
//	/safe   the same as /hdr but strips CR and LF first (not vulnerable)
//	/filter strips only the two-byte CRLF sequence, so a bare LF gets through
//	        (vulnerable, and reachable only by a bare-LF payload)
//	/body   echoes it into the response body (reflection, not a vulnerability)
//	/       a clean response
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "address to listen on")
	quiet := flag.Bool("quiet", false, "do not log requests")
	flag.Parse()
	logReq = !*quiet

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Fprintf(os.Stderr, "clrfkd-lab listening on http://%s\n", ln.Addr())
	fmt.Fprintf(os.Stderr, "routes: /hdr /cookie /safe /filter /body /\n")

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go handle(c)
	}
}

// logReq controls per-request logging, which makes the request cost of a scan
// directly countable.
var logReq = true

func handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(c)
	first, err := br.ReadString('\n')
	if err != nil {
		return
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	parts := strings.Fields(first)
	if len(parts) < 2 {
		return
	}
	target := parts[1]
	if logReq {
		fmt.Printf("%s %s\n", parts[0], target)
	}
	value := taintedValue(target)

	switch {
	case strings.HasPrefix(target, "/hdr"):
		write(c, 302, "Location: "+value, "")
	case strings.HasPrefix(target, "/cookie"):
		write(c, 200, "Set-Cookie: last="+value, "ok")
	case strings.HasPrefix(target, "/safe"):
		clean := strings.NewReplacer("\r", "", "\n", "").Replace(value)
		write(c, 302, "Location: "+clean, "")
	case strings.HasPrefix(target, "/filter"):
		// Strips the pair but not a lone LF, the mistake that makes bare-LF
		// payloads worth sending.
		write(c, 302, "Location: "+strings.ReplaceAll(value, "\r\n", ""), "")
	case strings.HasPrefix(target, "/body"):
		write(c, 404, "Content-Type: text/html", "<p>not found: "+value+"</p>")
	default:
		write(c, 200, "Content-Type: text/plain", "clrfkd-lab\n")
	}
}

func write(c net.Conn, status int, header, body string) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + reason(status) + "\r\n")
	if header != "" {
		b.WriteString(header + "\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	io.WriteString(c, b.String())
}

func reason(status int) string {
	switch status {
	case 200:
		return "OK"
	case 302:
		return "Found"
	case 404:
		return "Not Found"
	}
	return "Unknown"
}

// taintedValue returns the attacker-controlled string this fake application
// trusts: the "next" query parameter if it has one, otherwise the path.
func taintedValue(target string) string {
	path, query := target, ""
	if i := strings.Index(target, "?"); i >= 0 {
		path, query = target[:i], target[i+1:]
	}
	for _, pair := range strings.Split(query, "&") {
		if name, val, ok := strings.Cut(pair, "="); ok && name == "next" {
			return decodeOnce(val)
		}
	}
	return decodeOnce(path)
}

// decodeOnce is a lenient single-pass percent decoder, matching a sloppy
// application: malformed escapes pass through rather than being rejected.
func decodeOnce(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
