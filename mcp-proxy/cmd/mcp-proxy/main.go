package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
	"github.com/agent-receipts/ar/mcp-proxy/internal/proxy"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	receiptStore "github.com/agent-receipts/ar/sdk/go/store"
	"github.com/agent-receipts/ar/sdk/go/taxonomy"
	"github.com/google/uuid"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
// Falls back to the module version from Go's build info (set automatically
// for binaries installed with `go install`), then to "dev".
var version string

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "--version":
			fmt.Printf("mcp-proxy %s\n", resolveVersion())
			return
		case "list":
			cmdList(os.Args[2:])
			return
		case "inspect":
			cmdInspect(os.Args[2:])
			return
		case "verify":
			cmdVerify(os.Args[2:])
			return
		case "export":
			cmdExport(os.Args[2:])
			return
		case "stats":
			cmdStats(os.Args[2:])
			return
		case "timing":
			cmdTiming(os.Args[2:])
			return
		case "doctor":
			cmdDoctor(os.Args[2:])
			return
		case "serve":
			os.Args = append(os.Args[:1], os.Args[2:]...)
			// Fall through to serve.
		}
	}

	serve()
}

func serve() {
	var (
		dbPath       = flag.String("db", defaultDBPath("audit.db"), "SQLite audit database path")
		receiptDB    = flag.String("receipt-db", defaultDBPath("receipts.db"), "SQLite receipt store path")
		keyPath      = flag.String("key", "", "Ed25519 private key (PEM file)")
		taxonomyPath = flag.String("taxonomy", "", "Taxonomy mappings (JSON file)")
		rulesPath    = flag.String("rules", "", "Policy rules (YAML file)")
		serverName   = flag.String("name", "", "Server name for audit trail")
		issuerDID    = flag.String("issuer", "did:agent:mcp-proxy", "Issuer DID")
		issuerName   = flag.String("issuer-name", "", "Issuer name (e.g. Claude Code, Codex)")
		issuerModel  = flag.String("issuer-model", "", "AI model identifier (e.g. claude-sonnet-4-6)")
		operatorID   = flag.String("operator-id", "", "Operator DID (organisation running the agent)")
		operatorName = flag.String("operator-name", "", "Operator name (e.g. Anthropic)")
		principalDID = flag.String("principal", "did:user:unknown", "Principal DID")
		chainID      = flag.String("chain", "", "Chain ID (auto-generated if empty)")
		httpAddr     = flag.String("http", "127.0.0.1:0", "HTTP address for approval endpoints (default: random port; pass \"none\" to disable the approver)")
		approvalWait = flag.Duration("approval-timeout", 60*time.Second, "Maximum time to wait for HTTP approval when a policy rule pauses a tool call")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mcp-proxy [flags] <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "  Wraps an MCP server with audit, receipts, and policy enforcement.\n\n")
		fmt.Fprintf(os.Stderr, "Subcommands: serve, list, inspect, verify, export, stats, timing, doctor\n\n")
		fmt.Fprintf(os.Stderr, "  -version\n\tPrint version and exit\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]
	commandArgs := args[1:]

	// Server name defaults to command basename.
	if *serverName == "" {
		parts := strings.Split(command, "/")
		*serverName = parts[len(parts)-1]
	}

	// Chain ID defaults to new UUID.
	if *chainID == "" {
		*chainID = uuid.New().String()
	}

	// Open audit store.
	if err := ensureDBDir(*dbPath); err != nil {
		log.Fatalf("mcp-proxy: create audit db directory: %v", err)
	}
	auditDB, err := audit.Open(*dbPath)
	if err != nil {
		log.Fatalf("mcp-proxy: open audit db: %v", err)
	}
	defer auditDB.Close()

	sessionID := uuid.New().String()
	if err := auditDB.CreateSession(sessionID, *serverName, command); err != nil {
		log.Fatalf("mcp-proxy: create session: %v", err)
	}
	defer auditDB.EndSession(sessionID)

	// Open receipt store.
	if err := ensureDBDir(*receiptDB); err != nil {
		log.Fatalf("mcp-proxy: create receipt db directory: %v", err)
	}
	rStore, err := receiptStore.Open(*receiptDB)
	if err != nil {
		log.Fatalf("mcp-proxy: open receipt store: %v", err)
	}
	defer rStore.Close()

	// Load or generate key pair.
	var kp receipt.KeyPair
	if *keyPath != "" {
		privPEM, err := os.ReadFile(*keyPath)
		if err != nil {
			log.Fatalf("mcp-proxy: read key: %v", err)
		}
		kp.PrivateKey = string(privPEM)
	} else {
		kp, err = receipt.GenerateKeyPair()
		if err != nil {
			log.Fatalf("mcp-proxy: generate key: %v", err)
		}
		log.Printf("mcp-proxy: generated ephemeral key pair (public key printed below)")
		fmt.Fprintln(os.Stderr, kp.PublicKey)
	}

	// Load taxonomy mappings.
	var mappings []taxonomy.TaxonomyMapping
	if *taxonomyPath != "" {
		mappings, err = taxonomy.LoadTaxonomyConfig(*taxonomyPath)
		if err != nil {
			log.Fatalf("mcp-proxy: load taxonomy: %v", err)
		}
	}

	// Load policy rules.
	var rules []policy.Rule
	if *rulesPath != "" {
		rules, err = policy.LoadRules(*rulesPath)
		if err != nil {
			log.Fatalf("mcp-proxy: load rules: %v", err)
		}
	} else {
		rules = policy.DefaultRules()
	}
	engine := policy.NewEngine(rules)

	// Encryption.
	var encryptor *audit.Encryptor
	if key := os.Getenv("BEACON_ENCRYPTION_KEY"); key != "" {
		salt, err := auditDB.EncryptionSalt()
		if err != nil {
			log.Fatalf("mcp-proxy: init encryption salt: %v", err)
		}
		encryptor, err = audit.NewEncryptor(key, salt)
		if err != nil {
			log.Fatalf("mcp-proxy: init encryption: %v", err)
		}
	}

	// Intent tracker.
	intentTracker := audit.NewIntentTracker(auditDB, sessionID, 5*time.Second)

	// Approval channels for pause actions.
	approvalToken := generateToken(32)
	approvals := audit.NewApprovalManager()
	approvalURL := ""

	// Receipt chain state.
	sequence := 0
	var prevReceiptHash *string
	var seqMu sync.Mutex

	// Pending tool call requests (keyed by JSON-RPC id).
	type pendingCall struct {
		msgID          int64
		toolName       string
		arguments      map[string]any
		rawArgs        string
		opType         string
		riskScore      int
		reasons        []string
		policyAct      string
		approvedBy     string
		timestamp      time.Time
		policyEvalUs   int64
		approvalWaitUs int64
		forwardedAt    time.Time
	}
	pendingCalls := make(map[string]*pendingCall)
	var pendingMu sync.Mutex

	// Start HTTP server for approvals only when pause rules exist and the
	// operator hasn't disabled the approver via -http=none. Only the literal
	// "none" counts as an explicit opt-out; empty -http (e.g. `-http=`) is
	// treated as not-configured so the banner still warns.
	approverDisabled := strings.EqualFold(strings.TrimSpace(*httpAddr), "none")
	if engine.HasPauseRules() && !approverDisabled && *httpAddr != "" {
		ln, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			log.Fatalf("mcp-proxy: http server: %v", err)
		}
		approvalURL = "http://" + ln.Addr().String()
		// Human-readable line (one copy-pasteable string, no log timestamp prefix).
		fmt.Fprintf(os.Stderr, "mcp-proxy: approvals at %s (token: %s)\n", approvalURL, approvalToken)
		// Machine-readable line — minimal discovery primitive for future tooling.
		endpointJSON, err := json.Marshal(map[string]string{
			"event": "approval_endpoint",
			"url":   approvalURL,
			"token": approvalToken,
		})
		if err != nil {
			log.Printf("mcp-proxy: marshal approval endpoint discovery payload: %v", err)
			endpointJSON = []byte(`{"event":"approval_endpoint"}`)
		}
		fmt.Fprintln(os.Stderr, string(endpointJSON))
		go startHTTPServer(ln, approvals, approvalToken)
	}

	// Boot-time summary: one line covers the bulk of "why did my call fail?"
	// debugging. A WARN variant fires when the approver is absent but the
	// ruleset needs one, which is the #1 silent-failure mode. Explicit
	// -http=none is NOT treated as misconfiguration.
	emitStartupBanner(engine.Describe(), approvalURL, approverDisabled)

	handler := func(direction string, raw []byte, msg *proxy.Message) *proxy.HandlerResult {
		method := ""
		jsonrpcID := ""
		if msg != nil {
			method = msg.Method
			jsonrpcID = msg.IDString()
		}

		// Redact and optionally encrypt before storing.
		rawStr := string(raw)
		if len(rawStr) > 512*1024 {
			// Truncate at a rune boundary to avoid invalid UTF-8.
			truncated := rawStr[:512*1024]
			for i := len(truncated) - 1; i >= len(truncated)-4 && i >= 0; i-- {
				if utf8.RuneStart(truncated[i]) {
					truncated = truncated[:i]
					break
				}
			}
			rawStr = truncated + "...[truncated]"
		}
		redactedRaw := audit.Redact(rawStr)
		skipAudit := false
		if encryptor != nil {
			enc, encErr := encryptor.Encrypt(redactedRaw)
			if encErr != nil {
				log.Printf("mcp-proxy: encrypt message: %v", encErr)
				skipAudit = true
			} else {
				redactedRaw = enc
			}
		}

		var msgID int64
		if !skipAudit {
			var err error
			msgID, err = auditDB.LogMessage(sessionID, direction, jsonrpcID, method, redactedRaw)
			if err != nil {
				log.Printf("mcp-proxy: log message: %v", err)
			}
		}

		// Client → Server: intercept tool calls.
		if direction == "client_to_server" && msg != nil && msg.IsToolCall() {
			params, _ := msg.ParseToolCallParams()
			if params != nil {
				toolName := proxy.StripMCPPrefix(params.Name)
				opType := audit.ClassifyOperation(toolName)
				riskScore, reasons := audit.ScoreRisk(toolName, params.Arguments)

				evalStart := time.Now()
				decision := engine.Evaluate(policy.EvalContext{
					ToolName:      toolName,
					ServerName:    *serverName,
					OperationType: opType,
					RiskScore:     riskScore,
				})
				policyEvalUs := time.Since(evalStart).Microseconds()

				argJSON, _ := json.Marshal(params.Arguments)
				redactedArgs := audit.Redact(string(argJSON))
				if encryptor != nil {
					enc, encErr := encryptor.Encrypt(redactedArgs)
					if encErr != nil {
						log.Printf("mcp-proxy: encrypt args: %v", encErr)
					} else {
						redactedArgs = enc
					}
				}

				requestedAt := time.Now()
				pendingMu.Lock()
				pendingCalls[jsonrpcID] = &pendingCall{
					msgID:        msgID,
					toolName:     toolName,
					arguments:    params.Arguments,
					rawArgs:      redactedArgs,
					opType:       opType,
					riskScore:    riskScore,
					reasons:      reasons,
					policyAct:    decision.Action,
					timestamp:    requestedAt,
					policyEvalUs: policyEvalUs,
				}
				pendingMu.Unlock()

				var approvedBy string

				if decision.Action == "block" {
					log.Printf("mcp-proxy: BLOCKED %s (rule: %s, risk: %d)", toolName, decision.RuleName, riskScore)
					emitPolicyEvent(toolName, decision.RuleName, riskScore, "block", approvalURL, "blocked", 0)
					pendingMu.Lock()
					delete(pendingCalls, jsonrpcID)
					pendingMu.Unlock()
					recordRejectedToolCall(auditDB, sessionID, rejectedCall{
						requestMsgID: msgID,
						toolName:     toolName,
						arguments:    redactedArgs,
						opType:       opType,
						riskScore:    riskScore,
						reasons:      reasons,
						policyAction: "block",
						requestedAt:  requestedAt,
						policyEvalUs: policyEvalUs,
					})
					return &proxy.HandlerResult{
						Block:          true,
						ClientResponse: proxy.MakeErrorResponse(msg.ID, -32001, fmt.Sprintf("blocked by policy: %s", decision.Reason)),
					}
				}

				if decision.Action == "pause" {
					approvalID := generateToken(16)
					log.Printf("mcp-proxy: PAUSED %s (rule: %s, risk: %d) — approval id: %s", toolName, decision.RuleName, riskScore, approvalID)
					waitStart := time.Now()
					var approvalStatus audit.ApprovalStatus
					if approvalURL == "" {
						// No approver wired up — fail fast instead of timing out.
						approvalStatus = audit.ApprovalNoApprover
					} else {
						approvalStatus = approvals.WaitForApproval(approvalID, *approvalWait)
					}
					approvalWaitUs := time.Since(waitStart).Microseconds()
					if approvalStatus != audit.ApprovalApproved {
						log.Printf("mcp-proxy: DENIED %s (%s)", toolName, approvalStatus)
						emitPolicyEvent(toolName, decision.RuleName, riskScore, "pause", approvalURL, string(approvalStatus), approvalWaitUs/1000)
						code, message := approvalRejectionResponse(toolName, decision.RuleName, riskScore, approvalID, approvalStatus, *approvalWait)
						pendingMu.Lock()
						delete(pendingCalls, jsonrpcID)
						pendingMu.Unlock()
						recordRejectedToolCall(auditDB, sessionID, rejectedCall{
							requestMsgID:   msgID,
							toolName:       toolName,
							arguments:      redactedArgs,
							opType:         opType,
							riskScore:      riskScore,
							reasons:        reasons,
							policyAction:   "rejected",
							requestedAt:    requestedAt,
							policyEvalUs:   policyEvalUs,
							approvalWaitUs: approvalWaitUs,
						})
						return &proxy.HandlerResult{
							Block: true,
							ClientResponse: proxy.MakeErrorResponseWithData(
								msg.ID,
								code,
								message,
								map[string]any{
									"status":                  string(approvalStatus),
									"tool_name":               toolName,
									"rule_name":               decision.RuleName,
									"risk_score":              riskScore,
									"approval_id":             approvalID,
									"approval_url":            approvalURL,
									"approval_timeout_ms":     (*approvalWait).Milliseconds(),
									"approval_required":       true,
									"approval_token_required": true,
								},
							),
						}
					}
					approvedBy = "http"
					log.Printf("mcp-proxy: APPROVED %s", toolName)
					emitPolicyEvent(toolName, decision.RuleName, riskScore, "pause", approvalURL, "approved", approvalWaitUs/1000)
					pendingMu.Lock()
					if pc, ok := pendingCalls[jsonrpcID]; ok {
						pc.approvalWaitUs = approvalWaitUs
					}
					pendingMu.Unlock()
				}

				if approvedBy != "" {
					pendingMu.Lock()
					if pc, ok := pendingCalls[jsonrpcID]; ok {
						pc.approvedBy = approvedBy
					}
					pendingMu.Unlock()
				}

				if decision.Action == "flag" {
					log.Printf("mcp-proxy: FLAGGED %s (rule: %s, risk: %d)", toolName, decision.RuleName, riskScore)
				}

				// Record when request is forwarded to upstream for upstream_us calculation.
				pendingMu.Lock()
				if pc, ok := pendingCalls[jsonrpcID]; ok {
					pc.forwardedAt = time.Now()
				}
				pendingMu.Unlock()
			}
		}

		// Server → Client: pair response with request.
		if direction == "server_to_client" && msg != nil && msg.IsResponse() {
			pendingMu.Lock()
			pc, ok := pendingCalls[jsonrpcID]
			if ok {
				delete(pendingCalls, jsonrpcID)
			}
			pendingMu.Unlock()

			if ok {
				now := time.Now()

				// Compute upstream duration: time between forwarding and receiving response.
				var upstreamUs *int64
				if !pc.forwardedAt.IsZero() {
					u := now.Sub(pc.forwardedAt).Microseconds()
					upstreamUs = &u
				}

				resultStr := ""
				errorStr := ""
				if msg.Result != nil {
					resultStr = string(msg.Result)
				}
				if msg.Error != nil {
					errorStr = string(msg.Error)
				}

				redactedResult := audit.Redact(resultStr)
				// Keep pre-encryption copy for response_hash computation.
				receiptResponseBody := json.RawMessage(nil)
				if redactedResult != "" && json.Valid([]byte(redactedResult)) {
					receiptResponseBody = json.RawMessage(redactedResult)
				}
				redactedError := audit.Redact(errorStr)
				if encryptor != nil {
					if enc, encErr := encryptor.Encrypt(redactedResult); encErr != nil {
						log.Printf("mcp-proxy: encrypt result: %v", encErr)
					} else {
						redactedResult = enc
					}
					if enc, encErr := encryptor.Encrypt(redactedError); encErr != nil {
						log.Printf("mcp-proxy: encrypt error: %v", encErr)
					} else {
						redactedError = enc
					}
				}

				policyEvalUs := &pc.policyEvalUs
				var approvalWaitUs *int64
				if pc.approvalWaitUs > 0 {
					approvalWaitUs = &pc.approvalWaitUs
				}

				tcID, err := auditDB.InsertToolCall(audit.ToolCallRecord{
					SessionID:      sessionID,
					RequestMsgID:   pc.msgID,
					ResponseMsgID:  msgID,
					ToolName:       pc.toolName,
					Arguments:      pc.rawArgs,
					Result:         redactedResult,
					Error:          redactedError,
					OperationType:  pc.opType,
					RiskScore:      pc.riskScore,
					RiskReasons:    pc.reasons,
					PolicyAction:   pc.policyAct,
					ApprovedBy:     pc.approvedBy,
					RequestedAt:    pc.timestamp,
					RespondedAt:    now,
					PolicyEvalUs:   policyEvalUs,
					ApprovalWaitUs: approvalWaitUs,
					UpstreamUs:     upstreamUs,
				})
				if err != nil {
					log.Printf("mcp-proxy: insert tool call: %v", err)
				}

				// Track intent (only if tool call was stored).
				if err == nil {
					if trackErr := intentTracker.Track(tcID, pc.timestamp); trackErr != nil {
						log.Printf("mcp-proxy: track intent: %v", trackErr)
					}
				}

				// Emit receipt — hash the request parameters, not the response.
				classification := taxonomy.ClassifyToolCall(pc.toolName, mappings)

				// Fall back to prefix-based classifier when taxonomy has no mapping,
				// and align the risk level with the resolved operation type.
				actionType := classification.ActionType
				riskLevel := classification.RiskLevel
				if actionType == "unknown" {
					actionType = audit.ClassifyOperation(pc.toolName)
					switch actionType {
					case "read":
						riskLevel = receipt.RiskLow
					case "write":
						riskLevel = receipt.RiskMedium
					case "delete":
						riskLevel = receipt.RiskHigh
					case "execute":
						riskLevel = receipt.RiskHigh
					}
				}

				status := receipt.StatusSuccess
				if msg.Error != nil {
					status = receipt.StatusFailure
				}

				var argsHash string
				if canonical, canonErr := receipt.Canonicalize(pc.arguments); canonErr == nil {
					argsHash = receipt.SHA256Hash(canonical)
				} else {
					log.Printf("mcp-proxy: canonicalize args for hash: %v", canonErr)
				}

				receiptStart := time.Now()
				seqMu.Lock()
				sequence++
				currentSeq := sequence
				currentPrevHash := prevReceiptHash

				issuer := receipt.Issuer{
					ID:    *issuerDID,
					Name:  *issuerName,
					Model: *issuerModel,
				}
				if *operatorID != "" || *operatorName != "" {
					issuer.Operator = &receipt.Operator{
						ID:   *operatorID,
						Name: *operatorName,
					}
				}

				unsigned := receipt.Create(receipt.CreateInput{
					Issuer:    issuer,
					Principal: receipt.Principal{ID: *principalDID},
					Action: receipt.Action{
						Type:           actionType,
						ToolName:       pc.toolName,
						RiskLevel:      riskLevel,
						ParametersHash: argsHash,
						Target:         &receipt.ActionTarget{System: *serverName},
					},
					Outcome:      receipt.Outcome{Status: status},
					ResponseBody: receiptResponseBody,
					Chain: receipt.Chain{
						Sequence:            currentSeq,
						PreviousReceiptHash: currentPrevHash,
						ChainID:             *chainID,
					},
				})

				signed, err := receipt.Sign(unsigned, kp.PrivateKey, *issuerDID+"#key-1")
				if err != nil {
					log.Printf("mcp-proxy: sign receipt: %v", err)
					sequence-- // Rollback on sign failure too.
					seqMu.Unlock()
				} else {
					h, err := receipt.HashReceipt(signed)
					if err != nil {
						log.Printf("mcp-proxy: hash receipt: %v", err)
						sequence-- // Rollback.
						seqMu.Unlock()
					} else {
						if storeErr := rStore.Insert(signed, h); storeErr != nil {
							log.Printf("mcp-proxy: store receipt: %v", storeErr)
							sequence-- // Rollback — don't advance chain for unstored receipts.
							seqMu.Unlock()
						} else {
							prevReceiptHash = &h
							seqMu.Unlock()
						}
					}
				}

				// Update tool call with receipt signing duration.
				if tcID > 0 {
					receiptSignUs := time.Since(receiptStart).Microseconds()
					if updateErr := auditDB.UpdateReceiptSignUs(tcID, receiptSignUs); updateErr != nil {
						log.Printf("mcp-proxy: update receipt sign timing: %v", updateErr)
					}
				}
			}
		}

		return nil // Forward normally.
	}

	p := proxy.New(command, commandArgs, handler)
	log.Printf("mcp-proxy: session %s, server %s, chain %s", sessionID, *serverName, *chainID)
	if err := p.Run(); err != nil {
		log.Printf("mcp-proxy: %v", err)
		os.Exit(1)
	}
}

func buildApprovalDeniedMessage(toolName, ruleName string, riskScore int, approvalID string, status audit.ApprovalStatus, timeout time.Duration) string {
	switch status {
	case audit.ApprovalDenied:
		return fmt.Sprintf("tool call denied by approval workflow: tool=%s rule=%s risk=%d approval_id=%s", toolName, ruleName, riskScore, approvalID)
	case audit.ApprovalTimedOut:
		return fmt.Sprintf("tool call approval timed out after %s: tool=%s rule=%s risk=%d approval_id=%s", timeout, toolName, ruleName, riskScore, approvalID)
	case audit.ApprovalNoApprover:
		return fmt.Sprintf("tool call rejected: no approver configured for pause rule %q (pass -http=ADDR to enable, or -http=none to acknowledge): tool=%s risk=%d", ruleName, toolName, riskScore)
	default:
		return fmt.Sprintf("tool call denied by approval workflow: tool=%s rule=%s risk=%d approval_id=%s", toolName, ruleName, riskScore, approvalID)
	}
}

// approvalRejectionResponse returns the JSON-RPC error code and message for a
// non-approved pause outcome. -32002 covers the approved-channel cases (deny /
// timeout). -32003 is used for the no-approver case so clients can distinguish
// "configuration error" from "user rejected" and surface a different prompt.
func approvalRejectionResponse(toolName, ruleName string, riskScore int, approvalID string, status audit.ApprovalStatus, timeout time.Duration) (int, string) {
	code := -32002
	if status == audit.ApprovalNoApprover {
		code = -32003
	}
	return code, buildApprovalDeniedMessage(toolName, ruleName, riskScore, approvalID, status, timeout)
}

// emitStartupBanner prints a one-line policy/approver summary on stderr. When
// pause rules exist without a reachable approver AND the operator didn't opt
// out via -http=none, the line is marked WARN so misconfiguration is caught
// before the first failing tool call.
//
// "require approval" is reserved for pause rules; block rules are enforced
// without user interaction and are reported separately.
func emitStartupBanner(summary policy.Summary, approvalURL string, approverDisabled bool) {
	pauseCount := len(summary.PauseRules)
	blockCount := len(summary.BlockRules)

	approverState := approvalURL
	switch {
	case approverDisabled:
		approverState = "disabled"
	case approverState == "":
		approverState = "NONE"
	}

	level := "INFO"
	suffix := ""
	// Only warn on the accidental case: pause rules loaded, no approver,
	// and operator didn't explicitly opt out.
	if approvalURL == "" && !approverDisabled && pauseCount > 0 {
		level = "WARN"
		suffix = " — pause rules will fail (set -http=ADDR to enable approver, or -http=none to acknowledge)"
	}

	pauseDesc := ""
	if pauseCount > 0 {
		pauseDesc = fmt.Sprintf(" (%s)", strings.Join(summary.PauseRules, ", "))
	}
	blockDesc := ""
	if blockCount > 0 {
		blockDesc = fmt.Sprintf(", %d block (%s)", blockCount, strings.Join(summary.BlockRules, ", "))
	}

	rulesSuffix := ""
	if summary.TotalRules != summary.EnabledRules {
		rulesSuffix = fmt.Sprintf(" (%d disabled)", summary.TotalRules-summary.EnabledRules)
	}
	fmt.Fprintf(os.Stderr,
		"mcp-proxy: [%s] policy: %d rules enabled%s, %d require approval%s%s; approver: %s%s\n",
		level, summary.EnabledRules, rulesSuffix, pauseCount, pauseDesc, blockDesc, approverState, suffix,
	)

	// Machine-readable companion line for tooling.
	payload := map[string]any{
		"event":             "policy_banner",
		"level":             level,
		"rules_loaded":      summary.EnabledRules,
		"pause_rules":       summary.PauseRules,
		"block_rules":       summary.BlockRules,
		"approver_url":      approvalURL,
		"approver_set":      approvalURL != "",
		"approver_disabled": approverDisabled,
	}
	if b, err := json.Marshal(payload); err == nil {
		fmt.Fprintln(os.Stderr, string(b))
	}
}

// emitPolicyEvent writes one structured key=value log line per pause/block
// outcome. Cheap to grep, cheap to parse, small enough to ship to SIEMs.
// String values are %q-quoted so rule/tool names with spaces or "=" remain
// unambiguous when parsed.
func emitPolicyEvent(tool, rule string, risk int, action, approverURL, outcome string, durationMs int64) {
	approver := approverURL
	if approver == "" {
		approver = "NONE"
	}
	log.Printf("mcp-proxy: policy_event tool=%q rule=%q risk=%d action=%q approver=%q outcome=%q duration_ms=%d",
		tool, rule, risk, action, approver, outcome, durationMs)
}

// rejectedCall is the subset of pendingCall fields needed to persist a
// tool_calls row for a call that never reached the upstream server.
type rejectedCall struct {
	requestMsgID   int64
	toolName       string
	arguments      string
	opType         string
	riskScore      int
	reasons        []string
	policyAction   string
	requestedAt    time.Time
	policyEvalUs   int64
	approvalWaitUs int64
}

func recordRejectedToolCall(db *audit.Store, sessionID string, rc rejectedCall) {
	var approvalWait *int64
	if rc.approvalWaitUs > 0 {
		w := rc.approvalWaitUs
		approvalWait = &w
	}
	eval := rc.policyEvalUs
	if _, err := db.InsertToolCall(audit.ToolCallRecord{
		SessionID:     sessionID,
		RequestMsgID:  rc.requestMsgID,
		ToolName:      rc.toolName,
		Arguments:     rc.arguments,
		OperationType: rc.opType,
		RiskScore:     rc.riskScore,
		RiskReasons:   rc.reasons,
		PolicyAction:  rc.policyAction,
		RequestedAt:   rc.requestedAt,
		// RespondedAt intentionally zero — no upstream call happened.
		PolicyEvalUs:   &eval,
		ApprovalWaitUs: approvalWait,
	}); err != nil {
		log.Printf("mcp-proxy: insert rejected tool call: %v", err)
	}
}

// userHomeDir is overridable in tests so the fallback path in defaultDBPath
// can be exercised deterministically (clearing $HOME isn't enough on Unix —
// os.UserHomeDir can still resolve via /etc/passwd).
var userHomeDir = os.UserHomeDir

// defaultDBPath returns an absolute path under the user's home directory
// (`~/.agent-receipts/<name>`) for the given filename. MCP clients (Claude
// Desktop, Claude Code, Codex) spawn the proxy with an unwritable cwd, so a
// relative default would crash on first open. Falls back to the bare filename
// only if the home directory cannot be resolved to an absolute path — callers
// are expected to surface a clear error when that fallback is hit.
func defaultDBPath(name string) string {
	home, err := userHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return name
	}
	return filepath.Join(home, ".agent-receipts", name)
}

// ensureDBDir creates the parent directory of path with 0o700 permissions.
// SQLite can create the database file itself but not the directory holding it.
func ensureDBDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create database directory %q: %w", dir, err)
	}
	return nil
}

func generateToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("mcp-proxy: crypto/rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func startHTTPServer(ln net.Listener, approvals *audit.ApprovalManager, token string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tool-calls/", func(w http.ResponseWriter, r *http.Request) {
		// Validate bearer token.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		id := parts[3]
		action := parts[4]

		switch {
		case r.Method == "POST" && action == "approve":
			if approvals.Approve(id) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"status":"approved"}`)
			} else {
				http.Error(w, "no pending approval", http.StatusNotFound)
			}
		case r.Method == "POST" && action == "deny":
			if approvals.Deny(id) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"status":"denied"}`)
			} else {
				http.Error(w, "no pending approval", http.StatusNotFound)
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	if err := http.Serve(ln, mux); err != nil {
		log.Fatalf("mcp-proxy: http server: %v", err)
	}
}
