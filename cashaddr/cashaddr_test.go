package cashaddr

import (
	"fmt"
	"testing"
)

func TestKeystore_GenCashAddr(t *testing.T) {
	ks:=newKeyStore()
	fmt.Println(ks.GenCashAddr(MainNet))
}
func TestKeystore_GenLegacyAndCashAddr(t *testing.T) {
	ks:=newKeyStore()
	ks.GenLegacyAndCashAddr()
}

func TestBase32Decode(t *testing.T) {
	_,data,err:=Base32Decode(MainNet,"bitcoincash:qrc7w3nv32sg0pr485gqd4hcl8qgfvr96g35fym4g6")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(data) //得到的结果位公钥sha256-ripemd160的hash结果
}
