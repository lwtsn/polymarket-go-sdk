package ctf

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Client defines the CTF interface.
type Client interface {
	PrepareCondition(ctx context.Context, req *PrepareConditionRequest) (PrepareConditionResponse, error)
	ConditionID(ctx context.Context, req *ConditionIDRequest) (ConditionIDResponse, error)
	CollectionID(ctx context.Context, req *CollectionIDRequest) (CollectionIDResponse, error)
	PositionID(ctx context.Context, req *PositionIDRequest) (PositionIDResponse, error)

	// EnsureCollateralApproved checks whether the EOA's allowance for the CTF
	// contract is at least amount, and submits an approve(max) transaction if not.
	// Must be called before SplitPosition to avoid ERC-20 transfer reverts.
	EnsureCollateralApproved(ctx context.Context, token common.Address, amount *big.Int) error

	// EnsureERC20Approved ensures spender has max allowance for token from the EOA.
	// More general than EnsureCollateralApproved — use when the spender is not the CTF contract.
	EnsureERC20Approved(ctx context.Context, token, spender common.Address) error

	// EnsureConditionalApproved calls setApprovalForAll on the ConditionalTokens contract
	// so that operator can transfer the EOA's conditional tokens (ERC-1155).
	// Required before the exchange can settle SELL orders for YES tokens.
	EnsureConditionalApproved(ctx context.Context, operator common.Address) error

	// CollateralBalance returns the EOA's current on-chain balance for the given
	// ERC-20 token (e.g. native USDC on Polygon). Result is in raw token units
	// (6 decimals for USDC: 1_000_000 = $1.00). Requires backend + transactor.
	CollateralBalance(ctx context.Context, token common.Address) (*big.Int, error)

	// Transaction methods
	SplitPosition(ctx context.Context, req *SplitPositionRequest) (SplitPositionResponse, error)

	// SplitPositionAsync submits the split transaction and returns the tx hash
	// immediately, without waiting for mining. The mined channel receives nil
	// once confirmed, or an error, then closes. Callers MUST drain mined before
	// placing SELL orders — the CLOB checks on-chain state at order submission.
	SplitPositionAsync(ctx context.Context, req *SplitPositionRequest) (txHash common.Hash, mined <-chan error, err error)

	MergePositions(ctx context.Context, req *MergePositionsRequest) (MergePositionsResponse, error)
	RedeemPositions(ctx context.Context, req *RedeemPositionsRequest) (RedeemPositionsResponse, error)
	RedeemNegRisk(ctx context.Context, req *RedeemNegRiskRequest) (RedeemNegRiskResponse, error)
}
