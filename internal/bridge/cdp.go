package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
)

// Conn is a CDP client multiplexed over a Proc's pipe (id->response
// correlation; Target.attachToTarget flatten sessionId).
type Conn struct {
	proc *Proc
}

// cdpMessage is the minimal envelope the read-loop decodes: a response carries
// id (+result/error); an unsolicited event carries method (+params), no id.
type cdpMessage struct {
	ID        int64           `json:"id"`
	Result    json.RawMessage `json:"result"`
	Error     *cdpError       `json:"error"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
	SessionID string          `json:"sessionId"`
}

type cdpRequest struct {
	ID        int64  `json:"id"`
	Method    string `json:"method"`
	Params    any    `json:"params,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (e *cdpError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("cdp error %d: %s (%s)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("cdp error %d: %s", e.Code, e.Message)
}

// Dial returns a CDP client bound to the browser pipe for seeding, before any
// external client is accepted.
func (p *Proc) Dial(ctx context.Context) (*Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.closedErr(); err != nil {
		return nil, fmt.Errorf("cdp connection closed: %w", err)
	}
	return &Conn{proc: p}, nil
}

// Call issues one CDP command (sessionID "" = browser scope) and returns the
// raw result.
func (c *Conn) Call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	p := c.proc
	id := p.id.Add(1)
	payload, err := json.Marshal(cdpRequest{ID: id, Method: method, Params: params, SessionID: sessionID})
	if err != nil {
		return nil, fmt.Errorf("marshal cdp request: %w", err)
	}
	payload = append(payload, 0)

	ch := make(chan cdpMessage, 1)
	p.pendingMu.Lock()
	if p.dead != nil {
		dead := p.dead
		p.pendingMu.Unlock()
		return nil, fmt.Errorf("cdp connection closed: %w", dead)
	}
	p.pending[id] = ch
	p.pendingMu.Unlock()

	if err := p.write(payload); err != nil {
		p.removePending(id)
		return nil, err
	}

	select {
	case msg, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("cdp connection closed: %w", p.closedErr())
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("cdp %s: %w", method, msg.Error)
		}
		return msg.Result, nil
	case <-ctx.Done():
		p.removePending(id)
		return nil, ctx.Err()
	}
}

// Close detaches this caller; it deliberately leaves the shared pipe open for
// the relay that runs after seeding.
func (c *Conn) Close() error {
	return nil
}

// readLoop is the single consumer of the response/event pipe. It runs until the
// pipe errors, then fails every pending call. Once the relay sink is set it
// forwards every raw frame there verbatim and stops correlating ids.
func (p *Proc) readLoop() {
	br := bufio.NewReader(p.transport)
	for {
		raw, err := br.ReadBytes(0)
		if err != nil {
			p.fail(fmt.Errorf("cdp pipe read: %w", err))
			return
		}
		frame := raw[:len(raw)-1]
		if fn := p.relay.Load(); fn != nil {
			(*fn)(frame)
			continue
		}
		var msg cdpMessage
		if err := json.Unmarshal(frame, &msg); err != nil {
			p.fail(fmt.Errorf("cdp decode: %w", err))
			return
		}
		if msg.ID != 0 {
			p.deliver(msg)
			continue
		}
		if fn := p.events.Load(); fn != nil {
			(*fn)(msg)
		}
	}
}

func (p *Proc) deliver(msg cdpMessage) {
	p.pendingMu.Lock()
	ch, ok := p.pending[msg.ID]
	if ok {
		delete(p.pending, msg.ID)
	}
	p.pendingMu.Unlock()
	if ok {
		ch <- msg
	}
}

func (p *Proc) fail(err error) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	if p.dead == nil {
		p.dead = err
	}
	for id, ch := range p.pending {
		close(ch)
		delete(p.pending, id)
	}
}

func (p *Proc) removePending(id int64) {
	p.pendingMu.Lock()
	delete(p.pending, id)
	p.pendingMu.Unlock()
}

func (p *Proc) closedErr() error {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	return p.dead
}

func (p *Proc) write(b []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if _, err := p.transport.Write(b); err != nil {
		return fmt.Errorf("cdp pipe write: %w", err)
	}
	return nil
}

// writeFrame is the relay's client->browser path: it NUL-frames one raw CDP
// message and writes it to the pipe. Seeding uses Conn.Call instead.
func (p *Proc) writeFrame(b []byte) error {
	frame := make([]byte, len(b)+1)
	copy(frame, b)
	return p.write(frame)
}

func (p *Proc) setRelay(fn func([]byte)) { p.relay.Store(&fn) }

func (p *Proc) clearRelay() { p.relay.Store(nil) }
