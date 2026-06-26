// VoidHash CPU Miner
// Mines VoidCoin (VOID) using the VoidHash algorithm via Stratum v1.
//
// Usage:
//
//	voidhash-miner [flags]
//
// Flags:
//
//	-pool       Pool stratum address (default: stratum+tcp://pool.voidcoin.network:3532)
//	-user       Worker name / payout address
//	-pass       Worker password (default: x)
//	-threads    Number of CPU threads (default: all cores)
//	-solo       Solo mine via local voidcoind RPC instead of pool
//	-rpchost    voidcoind RPC host for solo mining (default: 127.0.0.1)
//	-rpcport    voidcoind RPC port for solo mining (default: 9332)
//	-rpcuser    voidcoind RPC user (default: void)
//	-rpcpass    voidcoind RPC password (default: voidpass)
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/voidhash-crypto/voidhash-miner/stratum"
	"github.com/voidhash-crypto/voidhash-miner/voidhash"
)

// ── Stats ─────────────────────────────────────────────────────────────────────

var (
	totalHashes  atomic.Int64
	acceptedShares atomic.Int64
	rejectedShares atomic.Int64
	startTime    = time.Now()
)

func printStats() {
	for {
		time.Sleep(30 * time.Second)
		hashes := totalHashes.Load()
		elapsed := time.Since(startTime).Seconds()
		hashrate := float64(hashes) / elapsed
		fmt.Printf("[stats] hashrate=%.3f H/s  accepted=%d  rejected=%d  total=%d\n",
			hashrate,
			acceptedShares.Load(),
			rejectedShares.Load(),
			hashes,
		)
	}
}

// ── Block header assembly ─────────────────────────────────────────────────────

func doubleSHA256(data []byte) []byte {
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

// buildHeader assembles the 76-byte block header (without nonce) from a job.
// VoidHash takes the header without nonce separately.
func buildHeader(job *stratum.Job, extranonce2 []byte) []byte {
	// Build coinbase transaction
	coinbase := append(job.CoinbaseHead, job.Extranonce1...)
	coinbase = append(coinbase, extranonce2...)
	coinbase = append(coinbase, job.CoinbaseTail...)
	coinbaseTXID := doubleSHA256(coinbase)

	// Build merkle root
	merkleRoot := coinbaseTXID
	for _, branch := range job.MerkleBranch {
		merkleRoot = doubleSHA256(append(merkleRoot, branch...))
	}

	// Decode prevhash (reversed for header)
	prevHashBytes, _ := hex.DecodeString(job.PrevHash)
	// Reverse each 4-byte chunk (Bitcoin byte-swapping)
	for i := 0; i < len(prevHashBytes)-3; i += 4 {
		prevHashBytes[i], prevHashBytes[i+3] = prevHashBytes[i+3], prevHashBytes[i]
		prevHashBytes[i+1], prevHashBytes[i+2] = prevHashBytes[i+2], prevHashBytes[i+1]
	}

	// Assemble header: version(4) + prevhash(32) + merkleroot(32) + time(4) + bits(4) = 76 bytes
	// Version, Time, Bits come as big-endian from stratum — reverse to little-endian
	rev := func(b []byte) []byte {
		r := make([]byte, len(b))
		for i := range b { r[i] = b[len(b)-1-i] }
		return r
	}
	header := make([]byte, 0, 76)
	header = append(header, rev(job.Version)...)
	header = append(header, prevHashBytes...)
	header = append(header, merkleRoot...)
	header = append(header, rev(job.Time)...)
	header = append(header, rev(job.Bits)...)
	return header
}

// ── Mining worker ─────────────────────────────────────────────────────────────

type ShareResult struct {
	Job         *stratum.Job
	Extranonce2 []byte
	Ntime       []byte
	Nonce       uint64
}

func mineWorker(
	threadID int,
	jobCh <-chan *stratum.Job,
	shareCh chan<- ShareResult,
	quit <-chan struct{},
) {
	var currentJob *stratum.Job
	var extranonce2 []byte
	var header []byte
	var target []byte
	var nonce uint64

	for {
		select {
		case <-quit:
			return
		case job := <-jobCh:
			currentJob = job
			// Build fresh extranonce2 for this thread
			extranonce2 = make([]byte, job.Extranonce2Len)
			binary.LittleEndian.PutUint32(extranonce2, uint32(threadID))
			header = buildHeader(job, extranonce2)
			target = job.Target
			nonce = uint64(rand.Int31()) // 32-bit nonces for pool compatibility
		default:
		}

		if currentJob == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Hash a batch of nonces
		for i := 0; i < 64; i++ {
			hash := voidhash.Hash(header, nonce)
			totalHashes.Add(1)

			if voidhash.MeetsTarget(hash, target) {
				shareCh <- ShareResult{
					Job:         currentJob,
					Extranonce2: extranonce2,
					Ntime:       currentJob.Time,
					Nonce:       nonce,
				}
				// Start fresh after finding a share
				nonce = uint64(rand.Int31()) // 32-bit nonces for pool compatibility
			}
			nonce = (nonce + 1) & 0xFFFFFFFF // keep in 32-bit range
		}
	}
}

// ── Pool mining ───────────────────────────────────────────────────────────────

func runPoolMiner(poolAddr, worker, password string, threads int) {
	// Strip stratum+tcp:// prefix
	addr := strings.TrimPrefix(poolAddr, "stratum+tcp://")

	fmt.Printf("[miner] connecting to pool %s\n", addr)
	fmt.Printf("[miner] worker: %s\n", worker)
	fmt.Printf("[miner] threads: %d\n", threads)
	fmt.Printf("[miner] algorithm: VoidHash (sequential memory-hard, SHA3-256T)\n")

	client := stratum.NewClient(addr, worker, password)

	quit := make(chan struct{})
	jobCh := make([]chan *stratum.Job, threads)
	shareCh := make(chan ShareResult, 16)

	for i := range jobCh {
		jobCh[i] = make(chan *stratum.Job, 1)
	}

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			mineWorker(id, jobCh[id], shareCh, quit)
		}(i)
	}

	// Job distributor
	client.OnJob = func(job *stratum.Job) {
		fmt.Printf("[job] new job %s  bits=%s  clean=%v\n",
			job.ID, hex.EncodeToString(job.Bits), job.CleanJobs)
		for _, ch := range jobCh {
			select {
			case ch <- job:
			default:
				// Replace stale job
				<-ch
				ch <- job
			}
		}
	}

	// Share submitter
	go func() {
		for share := range shareCh {
			fmt.Printf("[share] submitting job=%s nonce=%016x\n",
				share.Job.ID, share.Nonce)
			if err := client.SubmitShare(
				share.Job.ID,
				share.Extranonce2,
				share.Ntime,
				share.Nonce,
			); err != nil {
				fmt.Printf("[share] submit error: %v\n", err)
				rejectedShares.Add(1)
			} else {
				acceptedShares.Add(1)
				fmt.Printf("[share] ✓ accepted\n")
			}
		}
	}()

	go printStats()

	// Connect and run
	for {
		if err := client.Connect(); err != nil {
			fmt.Printf("[miner] connection failed: %v — retrying in 5s\n", err)
			time.Sleep(5 * time.Second)
			continue
		}
		fmt.Println("[miner] connected to pool")

		if err := client.Run(); err != nil {
			fmt.Printf("[miner] disconnected: %v — reconnecting in 5s\n", err)
			time.Sleep(5 * time.Second)
		}
	}
}

// ── Solo mining via RPC ───────────────────────────────────────────────────────

func rpcCall(host string, port int, user, pass, method string, params interface{}) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://%s:%d/", host, port),
		bytes.NewReader(body))
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result json.RawMessage `json:"result"`
		Error  interface{}     `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf("RPC error: %v", result.Error)
	}
	return result.Result, nil
}

// addrToP2PKH converts a VoidCoin address to a P2PKH locking script.
func addrToP2PKH(addr string) []byte {
	// Base58 decode
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range addr {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return []byte{0x6a} // OP_RETURN fallback
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	decoded := n.Bytes()
	// Pad to 25 bytes (1 version + 20 hash160 + 4 checksum)
	for len(decoded) < 25 {
		decoded = append([]byte{0}, decoded...)
	}
	if len(decoded) < 21 {
		return []byte{0x6a}
	}
	hash160 := decoded[1:21]
	// P2PKH: OP_DUP OP_HASH160 OP_DATA_20 <hash160> OP_EQUALVERIFY OP_CHECKSIG
	script := []byte{0x76, 0xa9, 0x14}
	script = append(script, hash160...)
	script = append(script, 0x88, 0xac)
	return script
}

// buildCoinbaseTx builds a minimal coinbase transaction.
func buildCoinbaseTx(addr string, value int64, height int64) []byte {
	// Height script: OP_PUSH + height bytes
	heightBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(heightBytes, uint32(height))
	// Trim trailing zeros
	for len(heightBytes) > 1 && heightBytes[len(heightBytes)-1] == 0 {
		heightBytes = heightBytes[:len(heightBytes)-1]
	}
	coinbaseScript := append([]byte{byte(len(heightBytes))}, heightBytes...)
	coinbaseScript = append(coinbaseScript, []byte("/VoidHash-Miner/")...)

	// Output script: P2PKH to miner address
	// Decode base58check address to get hash160
	outScript := addrToP2PKH(addr)

	var tx []byte
	// Version (4 bytes LE)
	tx = append(tx, []byte{0x01, 0x00, 0x00, 0x00}...)
	// Input count (1)
	tx = append(tx, 0x01)
	// Prev hash (32 zero bytes)
	tx = append(tx, make([]byte, 32)...)
	// Prev index (0xffffffff)
	tx = append(tx, []byte{0xff, 0xff, 0xff, 0xff}...)
	// Coinbase script length + script
	tx = append(tx, byte(len(coinbaseScript)))
	tx = append(tx, coinbaseScript...)
	// Sequence
	tx = append(tx, []byte{0xff, 0xff, 0xff, 0xff}...)
	// Output count (1)
	tx = append(tx, 0x01)
	// Value (8 bytes LE)
	valBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(valBytes, uint64(value))
	tx = append(tx, valBytes...)
	// Output script length + script
	tx = append(tx, byte(len(outScript)))
	tx = append(tx, outScript...)
	// Locktime
	tx = append(tx, []byte{0x00, 0x00, 0x00, 0x00}...)
	return tx
}

func runSoloMiner(rpcHost string, rpcPort int, rpcUser, rpcPass, mineAddr string, threads int) {
	fmt.Printf("[solo] mining to address: %s\n", mineAddr)
	fmt.Printf("[solo] node: %s:%d\n", rpcHost, rpcPort)
	fmt.Printf("[solo] threads: %d\n", threads)
	fmt.Printf("[solo] algorithm: VoidHash\n")

	go printStats()

	for {
		// Get block template
		tmplRaw, err := rpcCall(rpcHost, rpcPort, rpcUser, rpcPass,
			"getblocktemplate", []interface{}{map[string]interface{}{}})
		if err != nil {
			fmt.Printf("[solo] getblocktemplate error: %v — retrying in 5s\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var tmpl struct {
			Version       int    `json:"version"`
			PreviousHash  string `json:"previousblockhash"`
			Bits          string `json:"bits"`
			Target        string `json:"target"`
			Height        int64  `json:"height"`
			CurTime       int64  `json:"curtime"`
			CoinbaseValue int64  `json:"coinbasevalue"`
		}
		if err := json.Unmarshal(tmplRaw, &tmpl); err != nil {
			fmt.Printf("[solo] parse template error: %v\n", err)
			time.Sleep(2 * time.Second)
			continue
		}

		fmt.Printf("[solo] mining block %d  bits=%s\n", tmpl.Height, tmpl.Bits)

		// Parse target
		targetHex := tmpl.Target
		if len(targetHex) < 64 {
			targetHex = strings.Repeat("0", 64-len(targetHex)) + targetHex
		}
		target, _ := hex.DecodeString(targetHex)

		// Build coinbase transaction first so we can compute merkle root
		coinbaseTxData := buildCoinbaseTx(mineAddr, tmpl.CoinbaseValue, tmpl.Height)
		// Merkle root = doubleSHA256(coinbase) since there's only one tx
		merkleRoot := doubleSHA256(coinbaseTxData)

		prevHash, _ := hex.DecodeString(tmpl.PreviousHash)
		bitsBytes, _ := hex.DecodeString(tmpl.Bits)

		header := make([]byte, 76)
		binary.LittleEndian.PutUint32(header[0:4], uint32(tmpl.Version))
		copy(header[4:36], prevHash)
		copy(header[36:68], merkleRoot)
		binary.LittleEndian.PutUint32(header[68:72], uint32(tmpl.CurTime))
		// bits from RPC is big-endian hex, convert to LE for header
		if len(bitsBytes) == 4 {
			header[72] = bitsBytes[3]
			header[73] = bitsBytes[2]
			header[74] = bitsBytes[1]
			header[75] = bitsBytes[0]
		}

		// Mine with all threads
		found := make(chan uint64, 1)
		stopMining := make(chan struct{})

		targetBig := new(big.Int).SetBytes(target)

		var mineWg sync.WaitGroup
		for t := 0; t < threads; t++ {
			mineWg.Add(1)
			go func(threadID int) {
				defer mineWg.Done()
				startNonce := uint64(rand.Int63()) + uint64(threadID)*0x1000000000
				for nonce := startNonce; ; nonce++ {
					select {
					case <-stopMining:
						return
					default:
					}

					hash := voidhash.Hash(header, nonce)
					totalHashes.Add(1)

					hashBig := new(big.Int).SetBytes(hash[:])
					if hashBig.Cmp(targetBig) <= 0 {
						select {
						case found <- nonce:
						default:
						}
						return
					}
				}
			}(t)
		}

		// Wait for a solution or timeout (60s — new template)
		solved := false
		select {
		case nonce := <-found:
			close(stopMining)
			solved = true
			mineWg.Wait()

			fmt.Printf("[solo] found nonce: %016x\n", nonce)

			// Submit block (simplified — real submission needs full block)
			// Build the full header with nonce
			fullHeader := make([]byte, 84)
			copy(fullHeader, header)
			binary.LittleEndian.PutUint64(fullHeader[76:84], nonce)

			// Assemble full block: header + varint(1) + coinbase tx
		var blockBuf []byte
		blockBuf = append(blockBuf, fullHeader...)
		blockBuf = append(blockBuf, 0x01) // tx count = 1
		blockBuf = append(blockBuf, coinbaseTxData...)
		blockHex := hex.EncodeToString(blockBuf)
			result, err := rpcCall(rpcHost, rpcPort, rpcUser, rpcPass,
				"submitblock", []interface{}{blockHex})
			if err != nil {
				fmt.Printf("[solo] submitblock error: %v\n", err)
			} else {
				var rejection string
				json.Unmarshal(result, &rejection)
				if rejection == "" {
					acceptedShares.Add(1)
					fmt.Printf("[solo] ✓ block accepted! height=%d\n", tmpl.Height)
				} else {
					rejectedShares.Add(1)
					fmt.Printf("[solo] ✗ block rejected: %s\n", rejection)
				}
			}

		case <-time.After(60 * time.Second):
			close(stopMining)
			mineWg.Wait()
		}

		if !solved {
			// Get fresh template
			continue
		}
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	pool     := flag.String("pool", "stratum+tcp://pool.voidcoin.network:3532", "Pool stratum address")
	user     := flag.String("user", "", "Worker name / payout address (required)")
	pass     := flag.String("pass", "x", "Worker password")
	threads  := flag.Int("threads", runtime.NumCPU(), "Number of CPU mining threads")
	solo     := flag.Bool("solo", false, "Solo mine via local voidcoind RPC")
	rpcHost  := flag.String("rpchost", "127.0.0.1", "voidcoind RPC host (solo mode)")
	rpcPort  := flag.Int("rpcport", 9332, "voidcoind RPC port (solo mode)")
	rpcUser  := flag.String("rpcuser", "void", "voidcoind RPC username (solo mode)")
	rpcPass  := flag.String("rpcpass", "voidpass", "voidcoind RPC password (solo mode)")
	mineAddr := flag.String("addr", "", "Payout address for solo mining")
	flag.Parse()

	fmt.Println("╔════════════════════════════════════════════╗")
	fmt.Println("║         VoidHash CPU Miner  v1.0.0         ║")
	fmt.Println("║            Algorithm: VoidHash             ║")
	fmt.Println("║     https://github.com/VoidHash-Crypto     ║")
	fmt.Println("╚════════════════════════════════════════════╝")
	fmt.Println()

	runtime.GOMAXPROCS(*threads)

	if *solo {
		if *mineAddr == "" && *user == "" {
			fmt.Fprintln(os.Stderr, "error: -addr or -user required for solo mining")
			os.Exit(1)
		}
		addr := *mineAddr
		if addr == "" {
			addr = *user
		}
		go runSoloMiner(*rpcHost, *rpcPort, *rpcUser, *rpcPass, addr, *threads)
	} else {
		if *user == "" {
			fmt.Fprintln(os.Stderr, "error: -user (your VOID address) is required")
			fmt.Fprintln(os.Stderr, "usage: voidhash-miner -user YOUR_VOID_ADDRESS -pool stratum+tcp://pool:3532")
			os.Exit(1)
		}
		go runPoolMiner(*pool, *user, *pass, *threads)
	}

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	hashes := totalHashes.Load()
	elapsed := time.Since(startTime).Seconds()
	fmt.Printf("\n[miner] stopped. total=%d hashes in %.1fs = %.3f H/s\n",
		hashes, elapsed, float64(hashes)/elapsed)
	fmt.Printf("[miner] accepted=%d  rejected=%d\n",
		acceptedShares.Load(), rejectedShares.Load())
}
