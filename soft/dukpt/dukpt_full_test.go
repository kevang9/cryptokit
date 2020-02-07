package dukpt

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var BDK = []byte("4C98CEC85D5280D0CB138C6B4598D03D")
var KSN = []byte("504F5330320000200014")
var IPEK = []byte("e08906489d144c6c61d02eca20f9d236")
var PEK = []byte("ba4926a9a393d45e0b30f42f379cb968")

var PlainText = []byte("PAN0165502094004663386TR20375502094004663386=27082060000076100000DTV0042708CVV000FFFFFFF")
var CypherText = []byte("7c1fb70b3ee4f3518d8f8962261f1a384ebb7cd7372f3e11bc186711c9f1ef62fb38e9eddcb200a636fba82ac1f5e4789105e4cb641e6362be5902b29f6013db24c12acae7bac2d35554fa3790f34d224c93db9fa0b4c2bd")

func TestFullDukptFlow3DESCbcEncrypt(t *testing.T) {

	//Input Keys
	bdk := convertByteArrayToHexArray(BDK)
	ksn := convertByteArrayToHexArray(KSN)

	//Derive
	ipek, _ := DeriveIpekFromBdk(bdk, ksn)
	pek, _ := DerivePekFromIpek(ipek, ksn)

	t.Logf("BDK: %x", bdk)
	t.Logf("KSN: %x", ksn)
	t.Logf("IPEK: %x", ipek)
	t.Logf("PEK: %x", pek)

	assert.Equal(t, ipek, convertByteArrayToHexArray(IPEK), "Derived IPEK should be correct")
	assert.Equal(t, pek, convertByteArrayToHexArray(PEK), "Derived PEK should be correct")

	tdes, _ := des.NewTripleDESCipher(buildTdesKey(pek))
	cbc := cipher.NewCBCEncrypter(tdes, make([]byte, 8))

	result := make([]byte, len(CypherText))
	cbc.CryptBlocks(result, PlainText)

	t.Logf("ENCRYPTED: %x", string(result))

	assert.Equal(t, "7c1fb70b3ee4f3518d8f8962261f1a384ebb7cd7372f3e11bc186711c9f1ef62fb38e9eddcb200a636fba82ac1f5e4789105e4cb641e6362be5902b29f6013db24c12acae7bac2d35554fa3790f34d224c93db9fa0b4c2bd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", fmt.Sprintf("%x", string(result)))

}

func TestFullDukptFlow3DESCbcDecrypt(t *testing.T) {

	bdk := convertByteArrayToHexArray(BDK)
	ksn := convertByteArrayToHexArray(KSN)
	pek, _ := DerivePekFromBdk(bdk, ksn)

	t.Logf("BDK: %x", bdk)
	t.Logf("KSN: %x", ksn)
	t.Logf("PEK: %x", pek)

	assert.Equal(t, pek, convertByteArrayToHexArray(PEK), "Derived PEK should be correct")
	assert.NotNil(t, pek)

	tdes, err := des.NewTripleDESCipher(buildTdesKey(pek))
	if err != nil {
		t.Logf("ERR: %s", err)
	}
	cbc := cipher.NewCBCDecrypter(tdes, make([]byte, 8))

	result := make([]byte, len(PlainText))
	cbc.CryptBlocks(result, convertByteArrayToHexArray(CypherText))

	t.Logf("DECRYPTED: %x", string(result))

	assert.Equal(t, "PAN0165502094004663386TR20375502094004663386=27082060000076100000DTV0042708CVV000FFFFFFF", fmt.Sprintf("%s", string(result)))
}
