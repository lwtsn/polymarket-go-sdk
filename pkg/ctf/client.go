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

	// Transaction methods
	SplitPosition(ctx context.Context, req *SplitPositionRequest) (SplitPositionResponse, error)
	MergePositions(ctx context.Context, req *MergePositionsRequest) (MergePositionsResponse, error)
	RedeemPositions(ctx context.Context, req *RedeemPositionsRequest) (RedeemPositionsResponse, error)
	RedeemNegRisk(ctx context.Context, req *RedeemNegRiskRequest) (RedeemNegRiskResponse, error)
}
