package stratum

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── JSON types ────────────────────────────────────────────────────────────────

type Request struct {
	ID     interface{}   `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

type Response struct {
	ID     interface{}     `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  interface{}     `json:"error"`
}

type Notification struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// ── Job ───────────────────────────────────────────────────────────────────────

// Job holds all the data needed to attempt mining a block.
type Job struct {
	ID            string
	PrevHash      string
	CoinbaseHead  []byte // coinbase part 1 (before extranonce)
	CoinbaseTail  []byte // coinbase part 2 (after extranonce)
	MerkleBranch  [][]byte
	Version       []byte // 4 bytes LE
	Bits          []byte // 4 bytes LE
	Time          []byte // 4 bytes LE
	CleanJobs     bool
	Extranonce1   []byte
	Extranonce2Len int
	Target        []byte // 32 bytes, set from pool difficulty
}

// ── Client ────────────────────────────────────────────────────────────────────

// Client manages a Stratum v1 connection to a pool.
type Client struct {
	addr       string
	worker     string
	password   string
	conn       net.Conn
	reader     *bufio.Reader
	mu         sync.Mutex
	idCounter  atomic.Int64

	// Current state
	Extranonce1    []byte
	Extranonce2Len int
	Difficulty     float64
	CurrentJob     *Job
	jobMu          sync.RWMutex

	// Callbacks
	OnJob    func(job *Job)
	OnAccept func(shareID string)
	OnReject func(shareID string, reason string)

	quit chan struct{}
}

// NewClient creates a new Stratum client.
func NewClient(addr, worker, password string) *Client {
	return &Client{
		addr:     addr,
		worker:   worker,
		password: password,
		quit:     make(chan struct{}),
	}
}

// Connect dials the pool and performs the Stratum handshake.
func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.addr, err)
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)

	// Subscribe
	if err := c.send("mining.subscribe", []interface{}{
		"VoidHash-Miner/1.0.0", nil,
	}); err != nil {
		return err
	}

	// Read subscribe response
	resp, err := c.readResponse()
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	if err := c.handleSubscribeResult(resp.Result); err != nil {
		return fmt.Errorf("subscribe result: %w", err)
	}

	// Authorize
	if err := c.send("mining.authorize", []interface{}{c.worker, c.password}); err != nil {
		return err
	}

	return nil
}

// Run starts the message receive loop. Blocks until disconnected.
func (c *Client) Run() error {
	for {
		select {
		case <-c.quit:
			return nil
		default:
		}

		c.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		if err := c.handleMessage(line); err != nil {
			fmt.Printf("[stratum] message error: %v\n", err)
		}
	}
}

// SubmitShare submits a found share to the pool.
func (c *Client) SubmitShare(jobID string, extranonce2 []byte, ntime []byte, nonce uint64) error {
	nonceHex := fmt.Sprintf("%016x", nonce)
	ntimeHex := hex.EncodeToString(ntime)
	en2Hex := hex.EncodeToString(extranonce2)

	return c.send("mining.submit", []interface{}{
		c.worker,
		jobID,
		en2Hex,
		ntimeHex,
		nonceHex,
	})
}

// Disconnect closes the connection.
func (c *Client) Disconnect() {
	select {
	case <-c.quit:
	default:
		close(c.quit)
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (c *Client) send(method string, params []interface{}) error {
	id := c.idCounter.Add(1)
	req := Request{ID: id, Method: method, Params: params}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = c.conn.Write(data)
	return err
}

func (c *Client) readResponse() (*Response, error) {
	c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) handleMessage(data []byte) error {
	// Try as notification first (no id or id=null)
	var notif struct {
		ID     interface{}       `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
		Result json.RawMessage   `json:"result"`
		Error  interface{}       `json:"error"`
	}
	if err := json.Unmarshal(data, &notif); err != nil {
		return err
	}

	switch notif.Method {
	case "mining.notify":
		return c.handleNotify(notif.Params)
	case "mining.set_difficulty":
		return c.handleSetDifficulty(notif.Params)
	case "mining.set_extranonce":
		return c.handleSetExtranonce(notif.Params)
	case "":
		// Response to a request
		if notif.Error != nil {
			fmt.Printf("[stratum] error response: %v\n", notif.Error)
		}
		// Check if authorize response
		if notif.Result != nil {
			var ok bool
			if err := json.Unmarshal(notif.Result, &ok); err == nil && ok {
				fmt.Println("[stratum] authorized")
			}
		}
	}
	return nil
}

func (c *Client) handleSubscribeResult(result json.RawMessage) error {
	// Result: [[["mining.set_difficulty","..."],["mining.notify","..."]], extranonce1hex, extranonce2size]
	var arr []json.RawMessage
	if err := json.Unmarshal(result, &arr); err != nil || len(arr) < 3 {
		return fmt.Errorf("unexpected subscribe result: %s", result)
	}

	var en1Hex string
	if err := json.Unmarshal(arr[1], &en1Hex); err != nil {
		return err
	}
	en1, err := hex.DecodeString(en1Hex)
	if err != nil {
		return err
	}
	c.Extranonce1 = en1

	var en2Size int
	if err := json.Unmarshal(arr[2], &en2Size); err != nil {
		return err
	}
	c.Extranonce2Len = en2Size
	fmt.Printf("[stratum] subscribed: extranonce1=%s en2_len=%d\n", en1Hex, en2Size)
	return nil
}

func (c *Client) handleNotify(params []json.RawMessage) error {
	if len(params) < 9 {
		return fmt.Errorf("mining.notify: expected 9 params, got %d", len(params))
	}

	var jobID, prevHash, coinbase1Hex, coinbase2Hex string
	var merkleBranchHex []string
	var versionHex, bitsHex, timeHex string
	var cleanJobs bool

	json.Unmarshal(params[0], &jobID)
	json.Unmarshal(params[1], &prevHash)
	json.Unmarshal(params[2], &coinbase1Hex)
	json.Unmarshal(params[3], &coinbase2Hex)
	json.Unmarshal(params[4], &merkleBranchHex)
	json.Unmarshal(params[5], &versionHex)
	json.Unmarshal(params[6], &bitsHex)
	json.Unmarshal(params[7], &timeHex)
	json.Unmarshal(params[8], &cleanJobs)

	cb1, _ := hex.DecodeString(coinbase1Hex)
	cb2, _ := hex.DecodeString(coinbase2Hex)
	version, _ := hex.DecodeString(versionHex)
	bits, _ := hex.DecodeString(bitsHex)
	ntime, _ := hex.DecodeString(timeHex)

	var branches [][]byte
	for _, b := range merkleBranchHex {
		br, _ := hex.DecodeString(b)
		branches = append(branches, br)
	}

	// Compute target from bits
	target := bitsToTarget(bits)

	job := &Job{
		ID:             jobID,
		PrevHash:       prevHash,
		CoinbaseHead:   cb1,
		CoinbaseTail:   cb2,
		MerkleBranch:   branches,
		Version:        version,
		Bits:           bits,
		Time:           ntime,
		CleanJobs:      cleanJobs,
		Extranonce1:    c.Extranonce1,
		Extranonce2Len: c.Extranonce2Len,
		Target:         target,
	}

	c.jobMu.Lock()
	c.CurrentJob = job
	c.jobMu.Unlock()

	if c.OnJob != nil {
		c.OnJob(job)
	}
	return nil
}

func (c *Client) handleSetDifficulty(params []json.RawMessage) error {
	if len(params) == 0 {
		return nil
	}
	var diff float64
	json.Unmarshal(params[0], &diff)
	c.Difficulty = diff
	fmt.Printf("[stratum] difficulty set to %g\n", diff)
	return nil
}

func (c *Client) handleSetExtranonce(params []json.RawMessage) error {
	if len(params) < 2 {
		return nil
	}
	var en1Hex string
	var en2Size int
	json.Unmarshal(params[0], &en1Hex)
	json.Unmarshal(params[1], &en2Size)
	en1, _ := hex.DecodeString(en1Hex)
	c.Extranonce1 = en1
	c.Extranonce2Len = en2Size
	fmt.Printf("[stratum] extranonce updated: %s len=%d\n", en1Hex, en2Size)
	return nil
}

// GetCurrentJob returns the current job (thread-safe).
func (c *Client) GetCurrentJob() *Job {
	c.jobMu.RLock()
	defer c.jobMu.RUnlock()
	return c.CurrentJob
}

// ── Difficulty / target conversion ────────────────────────────────────────────

// bitsToTarget converts compact bits (4 bytes LE) to a 32-byte target.
func bitsToTarget(bits []byte) []byte {
	if len(bits) < 4 {
		return make([]byte, 32)
	}
	// bits is little-endian from the wire
	compact := uint32(bits[0]) | uint32(bits[1])<<8 | uint32(bits[2])<<16 | uint32(bits[3])<<24
	exp := compact >> 24
	mant := compact & 0x007fffff

	target := make([]byte, 32)
	if exp <= 3 {
		mant >>= 8 * (3 - exp)
		target[29] = byte(mant >> 16)
		target[30] = byte(mant >> 8)
		target[31] = byte(mant)
	} else {
		offset := 32 - int(exp)
		if offset >= 0 && offset < 32 {
			target[offset] = byte(mant >> 16)
			if offset+1 < 32 {
				target[offset+1] = byte(mant >> 8)
			}
			if offset+2 < 32 {
				target[offset+2] = byte(mant)
			}
		}
	}
	return target
}
