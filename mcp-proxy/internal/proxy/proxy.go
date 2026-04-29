// Package proxy implements a transparent MCP STDIO proxy.
package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime/debug"
	"sync"
	"time"
)

// HandlerResult tells the proxy what to do with a message.
type HandlerResult struct {
	// Block suppresses forwarding and sends ClientResponse to the client instead.
	Block bool
	// ClientResponse is sent to the client when Block is true.
	ClientResponse []byte
}

// Handler is called for each message flowing through the proxy.
// direction is "client_to_server" or "server_to_client".
// Return nil to forward normally.
type Handler func(direction string, raw []byte, msg *Message) *HandlerResult

// Proxy is a transparent STDIO MCP proxy.
type Proxy struct {
	command string
	args    []string
	handler Handler

	cmd          *exec.Cmd
	clientWriter io.Writer // os.Stdout — writes to MCP client
	startOnce    sync.Once
	writerMu     sync.Mutex
}

// New creates a new proxy that will spawn the given command.
func New(command string, args []string, handler Handler) *Proxy {
	return &Proxy{
		command: command,
		args:    args,
		handler: handler,
	}
}

// Run starts the child MCP server and proxies stdin/stdout bidirectionally.
// It blocks until the child process exits.
func (p *Proxy) Run() error {
	var firstCall bool
	p.startOnce.Do(func() {
		firstCall = true
	})
	if !firstCall {
		return fmt.Errorf("proxy already started")
	}

	p.clientWriter = os.Stdout

	p.cmd = exec.Command(p.command, p.args...)
	p.cmd.Stderr = os.Stderr

	serverIn, err := p.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	serverOut, err := p.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	// exits carries the pipe direction name when each goroutine finishes.
	// Capacity 2 so neither sender ever blocks.
	exits := make(chan string, 2)

	// Client → Server
	go func() {
		defer serverIn.Close()
		p.pipe(os.Stdin, serverIn, "client_to_server")
		exits <- "client_to_server"
	}()

	// Server → Client
	go func() {
		p.pipe(serverOut, os.Stdout, "server_to_client")
		exits <- "server_to_client"
	}()

	// Wait for the first pipe to finish, then kill the upstream so the
	// surviving pipe unblocks instead of blocking forever.
	first := <-exits
	log.Printf("mcp-proxy: pipe %s exited, shutting down", first)
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}

	// Drain the second exit with a short timeout so we capture the reason
	// but do not block forever.
	select {
	case second := <-exits:
		log.Printf("mcp-proxy: pipe %s exited", second)
	case <-time.After(2 * time.Second):
		log.Printf("mcp-proxy: second pipe did not exit within timeout")
	}

	return p.cmd.Wait()
}

// writeToClient sends a message to the MCP client (thread-safe).
func (p *Proxy) writeToClient(data []byte) error {
	p.writerMu.Lock()
	defer p.writerMu.Unlock()
	_, err := fmt.Fprintf(p.clientWriter, "%s\n", data)
	return err
}

func (p *Proxy) pipe(src io.Reader, dst io.Writer, direction string) {
	reader := bufio.NewReaderSize(src, 10*1024*1024) // 10MB buffer

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			// Trim trailing newline for processing.
			raw := line
			if len(raw) > 0 && raw[len(raw)-1] == '\n' {
				raw = raw[:len(raw)-1]
			}
			if len(raw) > 0 && raw[len(raw)-1] == '\r' {
				raw = raw[:len(raw)-1]
			}

			msg := ParseMessage(raw)

			if p.handler != nil {
				var result *HandlerResult
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("mcp-proxy: handler panic (%s): %v\n%s", direction, r, debug.Stack())
						}
					}()
					result = p.handler(direction, raw, msg)
				}()
				if result != nil && result.Block {
					// Send the block response to the client, not to dst.
					if writeErr := p.writeToClient(result.ClientResponse); writeErr != nil {
						log.Printf("mcp-proxy: write block response: %v", writeErr)
					}
					continue
				}
			}

			// For server→client, dst is os.Stdout which is also the
			// client writer. Use writeToClient to serialize all writes
			// and avoid interleaving with block responses.
			if direction == "server_to_client" {
				if writeErr := p.writeToClient(raw); writeErr != nil {
					log.Printf("mcp-proxy: write error (%s): %v", direction, writeErr)
					return
				}
			} else if _, writeErr := fmt.Fprintf(dst, "%s\n", raw); writeErr != nil {
				log.Printf("mcp-proxy: write error (%s): %v", direction, writeErr)
				return
			}
		}

		if err != nil {
			if err == io.EOF {
				log.Printf("mcp-proxy: pipe %s closed (EOF)", direction)
			} else {
				log.Printf("mcp-proxy: pipe %s read error: %v", direction, err)
			}
			return
		}
	}
}

// MakeErrorResponse creates a JSON-RPC error response for the given request ID.
func MakeErrorResponse(id json.RawMessage, code int, message string) []byte {
	return MakeErrorResponseWithData(id, code, message, nil)
}

// MakeErrorResponseWithData creates a JSON-RPC error response with optional
// structured error data for the given request ID.
func MakeErrorResponseWithData(id json.RawMessage, code int, message string, data map[string]any) []byte {
	errObj := map[string]any{
		"code":    code,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error":   errObj,
	}
	b, _ := json.Marshal(resp)
	return b
}
