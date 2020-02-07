package dukpt

import "encoding/hex"

func convertByteArrayToHexArray(byteArray []byte) []byte {
	hexArray := convertStringToHexArray(string(byteArray))
	return hexArray
}

func convertStringToHexArray(text string) []byte {
	hexArray, _ := hex.DecodeString(text)
	return hexArray
}
