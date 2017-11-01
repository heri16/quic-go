package wire

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wire Suite")
}

const (
	// a QUIC version that uses little endian encoding
	versionLittleEndian = protocol.Version37
	// a QUIC version that uses big endian encoding
	versionBigEndian = protocol.Version39
	// a QUIC version that uses stream 0 as the crypto stream.
	// That means it also has to use the MAX_DATA / MAX_STREAM_DATA and BLOCKED / STREAM_BLOCKED frames
	versionCryptoStream0 = protocol.VersionTLS
)

var _ = BeforeSuite(func() {
	Expect(utils.GetByteOrder(versionLittleEndian)).To(Equal(utils.LittleEndian))
	Expect(utils.GetByteOrder(versionBigEndian)).To(Equal(utils.BigEndian))
	Expect(utils.GetByteOrder(versionCryptoStream0)).To(Equal(utils.BigEndian))
	Expect(versionLittleEndian.CryptoStreamID()).To(Equal(protocol.StreamID(1)))
	Expect(versionBigEndian.CryptoStreamID()).To(Equal(protocol.StreamID(1)))
	Expect(versionCryptoStream0.CryptoStreamID()).To(Equal(protocol.StreamID(0)))
})
