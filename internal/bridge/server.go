package bridge

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// pingInterval keeps cross-host intermediaries from idling the relay closed.
const pingInterval = 30 * time.Second

// Server is the single-client, token-gated loopback WebSocket endpoint in front
// of a Proc's CDP pipe. The pipe has no TCP port, so this proxy is Chrome's sole
// external CDP door.
type Server struct {
	proc     *Proc
	ln       net.Listener
	httpSrv  *http.Server
	token    string
	uuid     string
	product  string
	protocol string
	url      string
	addr     string

	relayCancel context.CancelFunc // cancels the relay ctx; guarded by clientMu, no-op until a client attaches
	toClient    chan []byte
	closed      chan struct{}

	done     chan struct{}
	doneOnce sync.Once

	clientMu sync.Mutex
	client   *websocket.Conn
	accepted bool
}

// Serve starts the loopback WS relay for exactly one external client. token
// gates the connection; advertiseHost (host:port) is baked into the synthetic
// /json/version for a cross-host ssh -L client ("" => the local listener addr).
func (p *Proc) Serve(ctx context.Context, token, advertiseHost string) (*Server, error) {
	if token == "" {
		return nil, fmt.Errorf("bridge serve: empty token")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bridge listen: %w", err)
	}
	addr := ln.Addr().String()

	product, protocol, err := browserVersion(ctx, &Conn{proc: p})
	if err != nil {
		_ = ln.Close()
		return nil, err
	}

	host := advertiseHost
	if host == "" {
		host = addr
	}
	s := &Server{
		proc:        p,
		ln:          ln,
		token:       token,
		uuid:        p.BrowserUUID(),
		product:     product,
		protocol:    protocol,
		addr:        addr,
		url:         fmt.Sprintf("ws://%s/%s/devtools/browser/%s", host, token, p.BrowserUUID()),
		relayCancel: func() {},
		toClient:    make(chan []byte, 256),
		closed:      make(chan struct{}),
		done:        make(chan struct{}),
	}
	s.httpSrv = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = s.httpSrv.Serve(ln) }()
	return s, nil
}

// URL is the client-facing ws:// endpoint (token-bearing) to hand to
// agent-browser / connectOverCDP.
func (s *Server) URL() string {
	return s.url
}

// Addr is the local 127.0.0.1:<port> the loopback listener bound (the proxyport
// an ssh -L forwards).
func (s *Server) Addr() string {
	return s.addr
}

// Done is closed when the single external client disconnects (bridge should
// then tear down).
func (s *Server) Done() <-chan struct{} {
	return s.done
}

// Close stops the relay listener and drops the client connection. It does not
// kill Chrome; the daemon calls Proc.Close separately.
func (s *Server) Close() error {
	err := s.httpSrv.Close()
	s.teardown()
	return err
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	segments := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if subtle.ConstantTimeCompare([]byte(segments[0]), []byte(s.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rest := "/"
	if len(segments) == 2 {
		rest = "/" + segments[1]
	}
	switch rest {
	case "/json/version", "/json":
		s.serveVersion(w)
	case "/devtools/browser/" + s.uuid:
		s.serveWebSocket(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveVersion answers the discovery probe agent-browser connect and Playwright
// connectOverCDP fetch to find the ws endpoint.
func (s *Server) serveVersion(w http.ResponseWriter) {
	body, err := json.Marshal(map[string]string{
		"Browser":              s.product,
		"Protocol-Version":     s.protocol,
		"webSocketDebuggerUrl": s.url,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// serveWebSocket accepts exactly one client for the Server's lifetime and relays
// raw CDP frames both directions, byte-verbatim.
func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	s.clientMu.Lock()
	if s.accepted {
		s.clientMu.Unlock()
		http.Error(w, "bridge busy: one consumer per bridge", http.StatusConflict)
		return
	}
	s.accepted = true
	s.clientMu.Unlock()

	// Detach from the request context — the hijacked conn outlives the handler —
	// while inheriting its values; our own cancel drives teardown.
	relayCtx, relayCancel := context.WithCancel(context.WithoutCancel(r.Context()))

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		relayCancel()
		s.clientMu.Lock()
		s.accepted = false
		s.clientMu.Unlock()
		return
	}
	c.SetReadLimit(-1)

	s.clientMu.Lock()
	s.client = c
	s.relayCancel = relayCancel
	s.clientMu.Unlock()

	// Route every subsequent pipe message straight to this client, raw. Set the
	// relay before reading client commands so their responses aren't dropped.
	s.proc.setRelay(func(b []byte) {
		select {
		case s.toClient <- b:
		case <-s.closed:
		}
	})

	go s.writeLoop(relayCtx, c)
	go s.pingLoop(relayCtx, c)
	s.readLoop(relayCtx, c)
}

func (s *Server) readLoop(ctx context.Context, c *websocket.Conn) {
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			s.teardown()
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		if err := s.proc.writeFrame(data); err != nil {
			s.teardown()
			return
		}
	}
}

func (s *Server) writeLoop(ctx context.Context, c *websocket.Conn) {
	for {
		select {
		case b := <-s.toClient:
			wctx, cancel := context.WithTimeout(ctx, pingInterval)
			err := c.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				s.teardown()
				return
			}
		case <-s.closed:
			return
		}
	}
}

func (s *Server) pingLoop(ctx context.Context, c *websocket.Conn) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				s.teardown()
				return
			}
		case <-s.closed:
			return
		}
	}
}

func (s *Server) teardown() {
	s.doneOnce.Do(func() {
		s.proc.clearRelay()
		close(s.closed)
		s.clientMu.Lock()
		s.relayCancel()
		if s.client != nil {
			_ = s.client.CloseNow()
		}
		s.clientMu.Unlock()
		close(s.done)
	})
}

func browserVersion(ctx context.Context, c *Conn) (product, protocol string, err error) {
	raw, err := c.Call(ctx, "", "Browser.getVersion", nil)
	if err != nil {
		return "", "", fmt.Errorf("browser version: %w", err)
	}
	var v struct {
		Product         string `json:"product"`
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", "", fmt.Errorf("decode browser version: %w", err)
	}
	return v.Product, v.ProtocolVersion, nil
}
