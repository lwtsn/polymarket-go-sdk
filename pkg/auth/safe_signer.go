package auth

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	apitypes "github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// SafeSigner wraps an owner signer and a Safe address, providing the Signer interface
// for transactions that execute as the Safe. The owner signer is used to sign data,
// but all operations are attributed to the Safe address.
//
// For on-chain operations: the owner must have appropriate permissions on the Safe
// (e.g., configured as a module, delegate, or explicit signer depending on Safe setup).
type SafeSigner struct {
	owner    Signer
	safeAddr common.Address
}

// NewSafeSigner creates a SafeSigner that wraps an owner signer.
// The owner signer is used for signing, but operations are attributed to safeAddr.
func NewSafeSigner(owner Signer, safeAddr common.Address) *SafeSigner {
	return &SafeSigner{
		owner:    owner,
		safeAddr: safeAddr,
	}
}

// NewSignerForConfig creates the appropriate signer based on signature type.
// For EOA: returns the owner signer directly.
// For GNOSIS_SAFE: derives the Safe address and wraps the owner signer with SafeSigner.
// For PROXY: returns the owner signer (proxy support handled elsewhere).
// Returns the signer and (for Safe mode) the Safe address. For EOA/Proxy, safeAddr is the owner address.
func NewSignerForConfig(privateKeyHex string, signatureType SignatureType, chainID int64) (Signer, common.Address, error) {
	ownerSigner, err := NewPrivateKeySigner(privateKeyHex, chainID)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("create signer: %w", err)
	}

	ownerAddr := ownerSigner.Address()

	switch signatureType {
	case SignatureEOA, SignatureProxy:
		// For EOA and Proxy, use the owner signer directly
		return ownerSigner, ownerAddr, nil

	case SignatureGnosisSafe:
		// For Safe, derive the Safe address and wrap
		safeAddr, err := DeriveSafeWallet(ownerAddr)
		if err != nil {
			return nil, common.Address{}, fmt.Errorf("derive safe address: %w", err)
		}
		safeSigner := NewSafeSigner(ownerSigner, safeAddr)
		return safeSigner, safeAddr, nil

	default:
		return nil, common.Address{}, fmt.Errorf("unknown signature type: %d", signatureType)
	}
}

// Address returns the Safe address (not the owner address).
func (s *SafeSigner) Address() common.Address {
	return s.safeAddr
}

// OwnerAddress returns the owner's EOA address.
// This is used for API key derivation (L1 headers must match the signing key).
func (s *SafeSigner) OwnerAddress() common.Address {
	return s.owner.Address()
}

// OwnerSigner returns the underlying owner signer.
// Use this for CLOB client configuration (order signing) since API key is derived for owner address.
func (s *SafeSigner) OwnerSigner() Signer {
	return s.owner
}

// ChainID returns the chain ID from the owner signer.
func (s *SafeSigner) ChainID() *big.Int {
	return s.owner.ChainID()
}

// SignTypedData signs EIP-712 data using the owner's signer.
// The signature is valid for the owner address, but Safe validation depends on
// the Safe's configuration to accept the owner as a valid signer.
func (s *SafeSigner) SignTypedData(domain *apitypes.TypedDataDomain, types apitypes.Types, message apitypes.TypedDataMessage, primaryType string) ([]byte, error) {
	sig, err := s.owner.SignTypedData(domain, types, message, primaryType)
	if err != nil {
		return nil, fmt.Errorf("safe signer failed: owner signature failed: %w", err)
	}
	return sig, nil
}
