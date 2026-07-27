package auth

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)

// ConfiguredSigner encapsulates a signer and its address context for Safe/EOA operations.
// It determines which address to use for different operations (API key derivation vs on-chain).
// This is internal SDK use only.
type ConfiguredSigner struct {
	signer    Signer
	safeAddr  common.Address // Safe address (or EOA for non-Safe)
	ownerAddr common.Address // EOA address (for signing)
	sigType   SignatureType
}

// GetSigningAddress returns the address to use for EIP-712 signatures (API key derivation).
// For Safe: returns owner (EOA) address since signature comes from owner's private key
// For EOA: returns EOA address
func (cs *ConfiguredSigner) GetSigningAddress() common.Address {
	if cs.sigType == SignatureGnosisSafe {
		return cs.ownerAddr
	}
	return cs.safeAddr
}

// GetOperationAddress returns the address for on-chain operations and balance queries.
// For Safe: returns Safe address (operations execute as Safe)
// For EOA: returns EOA address
func (cs *ConfiguredSigner) GetOperationAddress() common.Address {
	return cs.safeAddr
}

// GetSigner returns the underlying signer for signing operations.
// For Safe: returns SafeSigner wrapping the owner signer
// For EOA: returns the owner signer directly
func (cs *ConfiguredSigner) GetSigner() Signer {
	return cs.signer
}

// GetCLOBSigner returns the signer to use for CLOB API operations and order signing.
// For Safe: returns the owner (EOA) signer because API key is derived for owner address
// For EOA: returns the owner signer directly
// Use this ONLY for CLOB client configuration, not for on-chain operations.
func (cs *ConfiguredSigner) GetCLOBSigner() Signer {
	if cs.sigType == SignatureGnosisSafe {
		// For Safe, extract the owner signer from the SafeSigner
		if safeSigner, ok := cs.signer.(*SafeSigner); ok {
			return safeSigner.OwnerSigner()
		}
	}
	return cs.signer
}

// GetSignatureType returns the signature type (EOA, Proxy, or Gnosis Safe)
func (cs *ConfiguredSigner) GetSignatureType() SignatureType {
	return cs.sigType
}

// IsSafeMode returns true if this is a Gnosis Safe signer
func (cs *ConfiguredSigner) IsSafeMode() bool {
	return cs.sigType == SignatureGnosisSafe
}

// NewConfiguredSignerFromConfig creates a fully configured signer from a private key and signature type.
// This is the ONLY function SDK users and connectors should use to create signers.
//
// For EOA: creates a PrivateKeySigner directly
// For Gnosis Safe: creates a PrivateKeySigner, derives Safe address, wraps in SafeSigner
// For Proxy: creates a PrivateKeySigner directly (proxy support handled elsewhere)
//
// Returns ConfiguredSigner with transparent address routing based on operation type.
func NewConfiguredSignerFromConfig(
	privateKeyHex string,
	signatureType SignatureType,
	chainID int64,
) (*ConfiguredSigner, error) {
	// Step 1: Create owner signer from private key
	ownerSigner, err := NewPrivateKeySigner(privateKeyHex, chainID)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	ownerAddr := ownerSigner.Address()
	var finalSigner Signer = ownerSigner
	safeAddr := ownerAddr

	// Step 2: If Safe mode, derive Safe address and wrap signer
	if signatureType == SignatureGnosisSafe {
		derivedSafeAddr, err := DeriveSafeWallet(ownerAddr)
		if err != nil {
			return nil, fmt.Errorf("derive safe address: %w", err)
		}
		safeAddr = derivedSafeAddr
		finalSigner = NewSafeSigner(ownerSigner, safeAddr)
	}

	// Step 3: Return fully configured signer with address context
	return &ConfiguredSigner{
		signer:    finalSigner,
		safeAddr:  safeAddr,
		ownerAddr: ownerAddr,
		sigType:   signatureType,
	}, nil
}
