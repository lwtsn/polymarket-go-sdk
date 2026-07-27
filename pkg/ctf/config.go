package ctf

import "github.com/ethereum/go-ethereum/common"

// Chain IDs.
const (
	PolygonChainID int64 = 137
	AmoyChainID    int64 = 80002
)

type contractConfig struct {
	ConditionalTokens common.Address
	NegRiskAdapter    *common.Address
}

var contractConfigs = map[int64]contractConfig{
	PolygonChainID: {
		ConditionalTokens: common.HexToAddress("0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"),
	},
	AmoyChainID: {
		ConditionalTokens: common.HexToAddress("0x69308FB512518e39F9b16112fA8d994F4e2Bf8bB"),
	},
}

// NegRiskExchangeAddress is the Polymarket NegRisk CTF Exchange on Polygon.
// USDC and conditional tokens must be approved to this address for CLOB orders to settle.
const NegRiskExchangeAddress = "0xC5d563A36AE78145C45a50134d48A1215220f80a"

var negRiskConfigs = map[int64]contractConfig{
	PolygonChainID: {
		ConditionalTokens: common.HexToAddress("0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"),
		NegRiskAdapter:    ptrAddress(common.HexToAddress("0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296")),
	},
	AmoyChainID: {
		ConditionalTokens: common.HexToAddress("0x69308FB512518e39F9b16112fA8d994F4e2Bf8bB"),
		NegRiskAdapter:    ptrAddress(common.HexToAddress("0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296")),
	},
}

func resolveConfig(chainID int64, negRisk bool) (contractConfig, bool) {
	if negRisk {
		cfg, ok := negRiskConfigs[chainID]
		return cfg, ok
	}
	cfg, ok := contractConfigs[chainID]
	return cfg, ok
}

func ptrAddress(addr common.Address) *common.Address {
	return &addr
}
