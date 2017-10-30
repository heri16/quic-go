package protocol

import (
	"fmt"
)

// VersionNumber is a version number as int
type VersionNumber int

// gQUIC version range as defined in the wiki: https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
const (
	gquicVersion0   = 0x51303030
	maxGquicVersion = 0x51303439
)

// The version numbers, making grepping easier
const (
	Version37 VersionNumber = gquicVersion0 + 3*0x100 + 0x7 + iota
	Version38
	Version39
)

// need a separate const block, to reset the iota to 0
const (
	Version41 VersionNumber = gquicVersion0 + 4*0x100 + 0x1 + iota // version 40 never existed, so don't export it
)

// non-gQUIC versions
const (
	VersionTLS         VersionNumber = 101
	VersionWhatever    VersionNumber = 0 // for when the version doesn't matter
	VersionUnsupported VersionNumber = -1
	VersionUnknown     VersionNumber = -2
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []VersionNumber{
	Version39,
	Version38,
	Version37,
}

// UsesTLS says if this QUIC version uses TLS 1.3 for the handshake
func (vn VersionNumber) UsesTLS() bool {
	return vn == VersionTLS
}

// UsesIETFStreamFrame says if the version uses the IETF format for the STREAM frame
func (vn VersionNumber) UsesIETFStreamFrame() bool {
	if vn == Version37 || vn == Version38 || vn == Version39 {
		return false
	}
	return true
}

// UsesIETFAckFrame says if the version uses the IETF format for the ACK frame
func (vn VersionNumber) UsesIETFAckFrame() bool {
	if vn == Version37 || vn == Version38 || vn == Version39 {
		return false
	}
	return true
}

func (vn VersionNumber) String() string {
	switch vn {
	case VersionWhatever:
		return "whatever"
	case VersionUnsupported:
		return "unsupported"
	case VersionUnknown:
		return "unknown"
	case VersionTLS:
		return "TLS dev version (WIP)"
	default:
		if vn > gquicVersion0 && vn <= maxGquicVersion {
			return fmt.Sprintf("gQUIC %d", vn.toGQUICVersion())
		}
		return fmt.Sprintf("%d", vn)
	}
}

// ToAltSvc returns the representation of the version for the H2 Alt-Svc parameters
func (vn VersionNumber) ToAltSvc() string {
	if vn > gquicVersion0 && vn <= maxGquicVersion {
		return fmt.Sprintf("%d", vn.toGQUICVersion())
	}
	return fmt.Sprintf("%d", vn)
}

func (vn VersionNumber) toGQUICVersion() int {
	return int(10*(vn-gquicVersion0)/0x100) + int(vn%0x10)
}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(supported []VersionNumber, v VersionNumber) bool {
	for _, t := range supported {
		if t == v {
			return true
		}
	}
	return false
}

// ChooseSupportedVersion finds the best version in the overlap of ours and theirs
// ours is a slice of versions that we support, sorted by our preference (descending)
// theirs is a slice of versions offered by the peer. The order does not matter
// if no suitable version is found, it returns VersionUnsupported
func ChooseSupportedVersion(ours, theirs []VersionNumber) VersionNumber {
	for _, ourVer := range ours {
		for _, theirVer := range theirs {
			if ourVer == theirVer {
				return ourVer
			}
		}
	}
	return VersionUnsupported
}
