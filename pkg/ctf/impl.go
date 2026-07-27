package ctf

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	sdkerrors "github.com/GoPolymarket/polymarket-go-sdk/pkg/errors"
	"github.com/GoPolymarket/polymarket-go-sdk/pkg/auth"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	conditionalTokensABI = `[{"inputs":[{"internalType":"address","name":"oracle","type":"address"},{"internalType":"bytes32","name":"questionId","type":"bytes32"},{"internalType":"uint256","name":"outcomeSlotCount","type":"uint256"}],"name":"prepareCondition","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"collateralToken","type":"address"},{"internalType":"bytes32","name":"parentCollectionId","type":"bytes32"},{"internalType":"bytes32","name":"conditionId","type":"bytes32"},{"internalType":"uint256[]","name":"partition","type":"uint256[]"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"splitPosition","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"collateralToken","type":"address"},{"internalType":"bytes32","name":"parentCollectionId","type":"bytes32"},{"internalType":"bytes32","name":"conditionId","type":"bytes32"},{"internalType":"uint256[]","name":"partition","type":"uint256[]"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"mergePositions","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"collateralToken","type":"address"},{"internalType":"bytes32","name":"parentCollectionId","type":"bytes32"},{"internalType":"bytes32","name":"conditionId","type":"bytes32"},{"internalType":"uint256[]","name":"indexSets","type":"uint256[]"}],"name":"redeemPositions","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
	negRiskAdapterABI    = `[{"inputs":[{"internalType":"bytes32","name":"conditionId","type":"bytes32"},{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"name":"redeemPositions","outputs":[],"stateMutability":"nonpayable","type":"function"}]`

	// Minimal ERC-20 ABI: allowance(), approve(), and balanceOf().
	erc20ABI = `[{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]`

	// Minimal ERC-1155 ABI: isApprovedForAll() and setApprovalForAll().
	erc1155ABI = `[{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"address","name":"operator","type":"address"}],"name":"isApprovedForAll","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"operator","type":"address"},{"internalType":"bool","name":"approved","type":"bool"}],"name":"setApprovalForAll","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
)

// Use unified error definitions from pkg/errors
var (
	ErrMissingRequest    = sdkerrors.ErrMissingRequest
	ErrMissingU256Value  = sdkerrors.ErrMissingU256Value
	ErrMissingBackend    = sdkerrors.ErrMissingBackend
	ErrMissingTransactor = sdkerrors.ErrMissingTransactor
	ErrNegRiskAdapter    = sdkerrors.ErrNegRiskAdapter
	ErrConfigNotFound    = sdkerrors.ErrConfigNotFound
)

type clientImpl struct {
	backend           Backend
	txOpts            *bind.TransactOpts
	conditionalTokens *bind.BoundContract
	negRiskAdapter    *bind.BoundContract
	ctfAddress        common.Address   // address of ConditionalTokens contract (spender for ERC-20 approvals)
	signer            auth.Signer      // optional signer for detecting SafeSigner and using owner address
}

// NewClient creates a lightweight CTF client for ID calculations.
// Transaction methods require a backend and transactor.
func NewClient() Client {
	return &clientImpl{}
}

// NewClientWithBackend creates a CTF client with a chain backend for transactions.
func NewClientWithBackend(backend Backend, txOpts *bind.TransactOpts, chainID int64) (Client, error) {
	return newClientWithConfig(backend, txOpts, chainID, false, nil)
}

// NewClientWithBackendSigner creates a CTF client with a chain backend and signer.
// The signer is used to detect SafeSigner and route approvals through the owner address.
func NewClientWithBackendSigner(backend Backend, txOpts *bind.TransactOpts, chainID int64, signer auth.Signer) (Client, error) {
	return newClientWithConfig(backend, txOpts, chainID, false, signer)
}

// NewClientWithNegRisk creates a CTF client with NegRisk adapter support.
func NewClientWithNegRisk(backend Backend, txOpts *bind.TransactOpts, chainID int64) (Client, error) {
	return newClientWithConfig(backend, txOpts, chainID, true, nil)
}

// NewClientWithNegRiskSigner creates a CTF client with NegRisk adapter support and a signer.
// The signer is used to detect SafeSigner and route approvals through the owner address.
func NewClientWithNegRiskSigner(backend Backend, txOpts *bind.TransactOpts, chainID int64, signer auth.Signer) (Client, error) {
	return newClientWithConfig(backend, txOpts, chainID, true, signer)
}

func newClientWithConfig(backend Backend, txOpts *bind.TransactOpts, chainID int64, negRisk bool, signer auth.Signer) (Client, error) {
	if backend == nil {
		return nil, ErrMissingBackend
	}
	cfg, ok := resolveConfig(chainID, negRisk)
	if !ok {
		return nil, ErrConfigNotFound
	}
	contractABI, err := abi.JSON(strings.NewReader(conditionalTokensABI))
	if err != nil {
		return nil, fmt.Errorf("parse conditional tokens ABI: %w", err)
	}
	contract := bind.NewBoundContract(cfg.ConditionalTokens, contractABI, backend, backend, backend)

	var neg *bind.BoundContract
	if cfg.NegRiskAdapter != nil {
		negABI, err := abi.JSON(strings.NewReader(negRiskAdapterABI))
		if err != nil {
			return nil, fmt.Errorf("parse neg risk ABI: %w", err)
		}
		neg = bind.NewBoundContract(*cfg.NegRiskAdapter, negABI, backend, backend, backend)
	}

	return &clientImpl{
		backend:           backend,
		txOpts:            txOpts,
		conditionalTokens: contract,
		negRiskAdapter:    neg,
		ctfAddress:        cfg.ConditionalTokens,
		signer:            signer,
	}, nil
}

func (c *clientImpl) PrepareCondition(ctx context.Context, req *PrepareConditionRequest) (PrepareConditionResponse, error) {
	if req == nil {
		return PrepareConditionResponse{}, ErrMissingRequest
	}
	if req.OutcomeSlotCount == nil {
		return PrepareConditionResponse{}, ErrMissingU256Value
	}
	tx, err := c.transact(ctx, c.conditionalTokens, "prepareCondition", req.Oracle, req.QuestionID, req.OutcomeSlotCount)
	if err != nil {
		return PrepareConditionResponse{}, err
	}
	return PrepareConditionResponse{TransactionHash: tx.Hash, BlockNumber: tx.BlockNumber}, nil
}

func (c *clientImpl) ConditionID(ctx context.Context, req *ConditionIDRequest) (ConditionIDResponse, error) {
	if req == nil {
		return ConditionIDResponse{}, ErrMissingRequest
	}
	if req.OutcomeSlotCount == nil {
		return ConditionIDResponse{}, ErrMissingU256Value
	}
	buf := make([]byte, 0, 20+32+32)
	buf = append(buf, req.Oracle.Bytes()...)
	buf = append(buf, req.QuestionID.Bytes()...)
	buf = append(buf, leftPad32(req.OutcomeSlotCount)...)
	hash := crypto.Keccak256Hash(buf)
	return ConditionIDResponse{ConditionID: hash}, nil
}

func (c *clientImpl) CollectionID(ctx context.Context, req *CollectionIDRequest) (CollectionIDResponse, error) {
	if req == nil {
		return CollectionIDResponse{}, ErrMissingRequest
	}
	if req.IndexSet == nil {
		return CollectionIDResponse{}, ErrMissingU256Value
	}
	buf := make([]byte, 0, 32+32+32)
	buf = append(buf, req.ParentCollectionID.Bytes()...)
	buf = append(buf, req.ConditionID.Bytes()...)
	buf = append(buf, leftPad32(req.IndexSet)...)
	hash := crypto.Keccak256Hash(buf)
	return CollectionIDResponse{CollectionID: hash}, nil
}

func (c *clientImpl) PositionID(ctx context.Context, req *PositionIDRequest) (PositionIDResponse, error) {
	if req == nil {
		return PositionIDResponse{}, ErrMissingRequest
	}
	buf := make([]byte, 0, 20+32)
	buf = append(buf, req.CollateralToken.Bytes()...)
	buf = append(buf, req.CollectionID.Bytes()...)
	hash := crypto.Keccak256Hash(buf)
	return PositionIDResponse{PositionID: new(big.Int).SetBytes(hash.Bytes())}, nil
}

func (c *clientImpl) SplitPosition(ctx context.Context, req *SplitPositionRequest) (SplitPositionResponse, error) {
	if req == nil {
		return SplitPositionResponse{}, ErrMissingRequest
	}
	if req.Amount == nil {
		return SplitPositionResponse{}, ErrMissingU256Value
	}
	if len(req.Partition) == 0 {
		return SplitPositionResponse{}, fmt.Errorf("partition is required")
	}
	tx, err := c.transact(ctx, c.conditionalTokens, "splitPosition",
		req.CollateralToken, req.ParentCollectionID, req.ConditionID, req.Partition, req.Amount)
	if err != nil {
		return SplitPositionResponse{}, err
	}
	return SplitPositionResponse{TransactionHash: tx.Hash, BlockNumber: tx.BlockNumber}, nil
}

func (c *clientImpl) MergePositions(ctx context.Context, req *MergePositionsRequest) (MergePositionsResponse, error) {
	if req == nil {
		return MergePositionsResponse{}, ErrMissingRequest
	}
	if req.Amount == nil {
		return MergePositionsResponse{}, ErrMissingU256Value
	}
	if len(req.Partition) == 0 {
		return MergePositionsResponse{}, fmt.Errorf("partition is required")
	}
	tx, err := c.transact(ctx, c.conditionalTokens, "mergePositions",
		req.CollateralToken, req.ParentCollectionID, req.ConditionID, req.Partition, req.Amount)
	if err != nil {
		return MergePositionsResponse{}, err
	}
	return MergePositionsResponse{TransactionHash: tx.Hash, BlockNumber: tx.BlockNumber}, nil
}

func (c *clientImpl) RedeemPositions(ctx context.Context, req *RedeemPositionsRequest) (RedeemPositionsResponse, error) {
	if req == nil {
		return RedeemPositionsResponse{}, ErrMissingRequest
	}
	if len(req.IndexSets) == 0 {
		return RedeemPositionsResponse{}, fmt.Errorf("index_sets is required")
	}
	tx, err := c.transact(ctx, c.conditionalTokens, "redeemPositions",
		req.CollateralToken, req.ParentCollectionID, req.ConditionID, req.IndexSets)
	if err != nil {
		return RedeemPositionsResponse{}, err
	}
	return RedeemPositionsResponse{TransactionHash: tx.Hash, BlockNumber: tx.BlockNumber}, nil
}

func (c *clientImpl) RedeemNegRisk(ctx context.Context, req *RedeemNegRiskRequest) (RedeemNegRiskResponse, error) {
	if req == nil {
		return RedeemNegRiskResponse{}, ErrMissingRequest
	}
	if len(req.Amounts) == 0 {
		return RedeemNegRiskResponse{}, fmt.Errorf("amounts is required")
	}
	if c.negRiskAdapter == nil {
		return RedeemNegRiskResponse{}, ErrNegRiskAdapter
	}
	tx, err := c.transact(ctx, c.negRiskAdapter, "redeemPositions", req.ConditionID, req.Amounts)
	if err != nil {
		return RedeemNegRiskResponse{}, err
	}
	return RedeemNegRiskResponse{TransactionHash: tx.Hash, BlockNumber: tx.BlockNumber}, nil
}

// EnsureCollateralApproved checks the EOA's ERC-20 allowance for the CTF
// contract. If the allowance is below amount, it submits an approve(max)
// transaction and waits for it to be mined before returning.
//
// For SafeSigner: Detects and uses the owner (EOA) address for approvals,
// since the signature must come from the owner's private key.
func (c *clientImpl) EnsureCollateralApproved(ctx context.Context, token common.Address, amount *big.Int) error {
	if c.backend == nil {
		return ErrMissingBackend
	}
	if c.txOpts == nil {
		return ErrMissingTransactor
	}

	// Determine the address to use for approvals.
	// For SafeSigner: use owner address (the actual signer).
	// For EOA: use the transactor's address.
	approvingAddr := c.txOpts.From
	if c.signer != nil {
		if safeSigner, ok := c.signer.(*auth.SafeSigner); ok {
			approvingAddr = safeSigner.OwnerAddress()
		}
	}

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return fmt.Errorf("parse erc20 ABI: %w", err)
	}
	erc20 := bind.NewBoundContract(token, parsedABI, c.backend, c.backend, c.backend)

	// ── Read current allowance ────────────────────────────────────────────────
	var results []interface{}
	callOpts := &bind.CallOpts{Context: ctx, From: approvingAddr}
	if err := erc20.Call(callOpts, &results, "allowance", approvingAddr, c.ctfAddress); err != nil {
		return fmt.Errorf("read allowance: %w", err)
	}
	if len(results) == 0 {
		return fmt.Errorf("allowance returned no result")
	}
	allowance, ok := results[0].(*big.Int)
	if !ok || allowance == nil {
		return fmt.Errorf("unexpected allowance result type")
	}

	// Already approved — nothing to do.
	if allowance.Cmp(amount) >= 0 {
		return nil
	}

	// ── Submit approve(spender, max) ──────────────────────────────────────────
	// Use the same address for signing that we used for checking allowance.
	maxApproval := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)) // 2^256 - 1
	opts := *c.txOpts
	opts.Context = ctx
	opts.From = approvingAddr  // Ensure signature matches the address
	tx, err := erc20.Transact(&opts, "approve", c.ctfAddress, maxApproval)
	if err != nil {
		return fmt.Errorf("approve usdc: %w", err)
	}
	if _, err := bind.WaitMined(ctx, c.backend, tx); err != nil {
		return fmt.Errorf("wait approve receipt: %w", err)
	}
	return nil
}

// EnsureERC20Approved grants spender max uint256 allowance for token from the EOA,
// if the current allowance is below the threshold. Use this to approve the CTF
// Exchange contract for USDC so buy order settlement can pull funds.
//
// For SafeSigner: Detects and uses the owner (EOA) address for approvals.
func (c *clientImpl) EnsureERC20Approved(ctx context.Context, token, spender common.Address) error {
	if c.backend == nil {
		return ErrMissingBackend
	}
	if c.txOpts == nil {
		return ErrMissingTransactor
	}

	// Determine the address to use for approvals.
	approvingAddr := c.txOpts.From
	if c.signer != nil {
		if safeSigner, ok := c.signer.(*auth.SafeSigner); ok {
			approvingAddr = safeSigner.OwnerAddress()
		}
	}

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return fmt.Errorf("parse erc20 ABI: %w", err)
	}
	erc20 := bind.NewBoundContract(token, parsedABI, c.backend, c.backend, c.backend)

	var results []interface{}
	callOpts := &bind.CallOpts{Context: ctx, From: approvingAddr}
	if err := erc20.Call(callOpts, &results, "allowance", approvingAddr, spender); err != nil {
		return fmt.Errorf("read allowance: %w", err)
	}
	if len(results) == 0 {
		return fmt.Errorf("allowance returned no result")
	}
	allowance, ok := results[0].(*big.Int)
	if !ok || allowance == nil {
		return fmt.Errorf("unexpected allowance result type")
	}

	// Use a high threshold — if already approved for > 1B USDC we're fine.
	threshold := new(big.Int).Mul(big.NewInt(1_000_000_000), big.NewInt(1_000_000))
	if allowance.Cmp(threshold) >= 0 {
		return nil
	}

	maxApproval := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	opts := *c.txOpts
	opts.Context = ctx
	opts.From = approvingAddr  // Ensure signature matches the address
	tx, err := erc20.Transact(&opts, "approve", spender, maxApproval)
	if err != nil {
		return fmt.Errorf("approve erc20: %w", err)
	}
	if _, err := bind.WaitMined(ctx, c.backend, tx); err != nil {
		return fmt.Errorf("wait approve receipt: %w", err)
	}
	return nil
}

// EnsureConditionalApproved calls setApprovalForAll on the ConditionalTokens contract
// so that operator (the exchange) can transfer the EOA's ERC-1155 conditional tokens.
// Required before the exchange can settle SELL orders for YES tokens.
//
// For SafeSigner: Detects and uses the owner (EOA) address for approvals.
func (c *clientImpl) EnsureConditionalApproved(ctx context.Context, operator common.Address) error {
	if c.backend == nil {
		return ErrMissingBackend
	}
	if c.txOpts == nil {
		return ErrMissingTransactor
	}

	// Determine the address to use for approvals.
	approvingAddr := c.txOpts.From
	if c.signer != nil {
		if safeSigner, ok := c.signer.(*auth.SafeSigner); ok {
			approvingAddr = safeSigner.OwnerAddress()
		}
	}

	parsedABI, err := abi.JSON(strings.NewReader(erc1155ABI))
	if err != nil {
		return fmt.Errorf("parse erc1155 ABI: %w", err)
	}
	ctf := bind.NewBoundContract(c.ctfAddress, parsedABI, c.backend, c.backend, c.backend)

	// Check if already approved.
	var results []interface{}
	callOpts := &bind.CallOpts{Context: ctx, From: approvingAddr}
	if err := ctf.Call(callOpts, &results, "isApprovedForAll", approvingAddr, operator); err != nil {
		return fmt.Errorf("read isApprovedForAll: %w", err)
	}
	if len(results) > 0 {
		if approved, ok := results[0].(bool); ok && approved {
			return nil
		}
	}

	opts := *c.txOpts
	opts.Context = ctx
	opts.From = approvingAddr  // Ensure signature matches the address
	tx, err := ctf.Transact(&opts, "setApprovalForAll", operator, true)
	if err != nil {
		return fmt.Errorf("setApprovalForAll: %w", err)
	}
	if _, err := bind.WaitMined(ctx, c.backend, tx); err != nil {
		return fmt.Errorf("wait setApprovalForAll receipt: %w", err)
	}
	return nil
}

// CollateralBalance reads the EOA's ERC-20 balance for token via an eth_call.
// Uses the same Polygon RPC backend and EOA address as all other CTF operations.
func (c *clientImpl) CollateralBalance(ctx context.Context, token common.Address) (*big.Int, error) {
	if c.backend == nil {
		return nil, ErrMissingBackend
	}
	if c.txOpts == nil {
		return nil, ErrMissingTransactor
	}

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, fmt.Errorf("parse erc20 ABI: %w", err)
	}
	erc20 := bind.NewBoundContract(token, parsedABI, c.backend, c.backend, c.backend)

	var results []interface{}
	callOpts := &bind.CallOpts{Context: ctx, From: c.txOpts.From}
	if err := erc20.Call(callOpts, &results, "balanceOf", c.txOpts.From); err != nil {
		return nil, fmt.Errorf("balanceOf: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("balanceOf returned no result")
	}
	balance, ok := results[0].(*big.Int)
	if !ok || balance == nil {
		return nil, fmt.Errorf("unexpected balanceOf result type")
	}
	return balance, nil
}

type txResult struct {
	Hash        common.Hash
	BlockNumber uint64
}

func (c *clientImpl) transact(ctx context.Context, contract *bind.BoundContract, method string, args ...interface{}) (txResult, error) {
	if c.backend == nil || contract == nil {
		return txResult{}, ErrMissingBackend
	}
	if c.txOpts == nil {
		return txResult{}, ErrMissingTransactor
	}
	opts := *c.txOpts
	opts.Context = ctx

	tx, err := contract.Transact(&opts, method, args...)
	if err != nil {
		return txResult{}, fmt.Errorf("send %s: %w", method, err)
	}
	receipt, err := bind.WaitMined(ctx, c.backend, tx)
	if err != nil {
		return txResult{}, fmt.Errorf("wait %s receipt: %w", method, err)
	}
	if receipt == nil || receipt.BlockNumber == nil {
		return txResult{}, errors.New("receipt missing block number")
	}
	return txResult{Hash: tx.Hash(), BlockNumber: receipt.BlockNumber.Uint64()}, nil
}

// transactAsync submits a transaction and returns the hash immediately without
// waiting for it to be mined. The returned channel receives nil once mined, or
// an error if mining fails, then closes. Uses context.Background() for
// WaitMined so the goroutine outlives the caller's context — the tx is already
// broadcast and must always be allowed to settle.
func (c *clientImpl) transactAsync(ctx context.Context, contract *bind.BoundContract, method string, args ...interface{}) (common.Hash, <-chan error, error) {
	if c.backend == nil || contract == nil {
		return common.Hash{}, nil, ErrMissingBackend
	}
	if c.txOpts == nil {
		return common.Hash{}, nil, ErrMissingTransactor
	}
	opts := *c.txOpts
	opts.Context = ctx

	tx, err := contract.Transact(&opts, method, args...)
	if err != nil {
		return common.Hash{}, nil, fmt.Errorf("send %s: %w", method, err)
	}

	mined := make(chan error, 1)
	backend := c.backend
	go func() {
		defer close(mined)
		if _, err := bind.WaitMined(context.Background(), backend, tx); err != nil {
			mined <- fmt.Errorf("wait %s receipt: %w", method, err)
		}
	}()

	return tx.Hash(), mined, nil
}

// SplitPositionAsync is the non-blocking variant of SplitPosition.
// It submits the split transaction and returns the tx hash immediately.
// The mined channel receives nil once the block is confirmed, or an error
// if the wait fails. Callers MUST drain mined before placing SELL orders.
func (c *clientImpl) SplitPositionAsync(ctx context.Context, req *SplitPositionRequest) (common.Hash, <-chan error, error) {
	if req == nil {
		return common.Hash{}, nil, ErrMissingRequest
	}
	if req.Amount == nil {
		return common.Hash{}, nil, ErrMissingU256Value
	}
	if len(req.Partition) == 0 {
		return common.Hash{}, nil, fmt.Errorf("partition is required")
	}
	return c.transactAsync(ctx, c.conditionalTokens, "splitPosition",
		req.CollateralToken, req.ParentCollectionID, req.ConditionID, req.Partition, req.Amount)
}

func leftPad32(value *big.Int) []byte {
	if value == nil {
		return make([]byte, 32)
	}
	raw := value.Bytes()
	if len(raw) >= 32 {
		return raw[len(raw)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(raw):], raw)
	return padded
}
