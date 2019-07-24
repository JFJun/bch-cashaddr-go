package cashaddr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/ripemd160"
	"math"
)

// cashaddr的 prefixes
const (
	RegTest = "bchreg"
	TestNet = "bchtest"
	MainNet = "bitcoincash"
)
//  cashaddress 类型
const (
	P2KH uint8 = 0
	P2SH uint8 = 1
)


//bch的cashaddr地址生成

type Keystore struct {
	Priv *ecdsa.PrivateKey
	Pub []byte
}

func newKeyStore()*Keystore{
	var ks Keystore
	curve :=elliptic.P256()
	private,_:=ecdsa.GenerateKey(curve,rand.Reader)  //获取私钥
	var pubKey []byte
	if (private.PublicKey.Y.Uint64()%2==0){
		pubKey = append(pubKey,0x02)
		pubKey = append(pubKey,private.PublicKey.X.Bytes()...)
	}else{
		pubKey = append(pubKey,0x03)
		pubKey = append(pubKey,private.PublicKey.X.Bytes()...)
	}
	ks.Priv = private
	ks.Pub = pubKey
	return &ks
}

//计算原始地址和cashaddr
func (ks *Keystore)GenLegacyAndCashAddr(){
	//计算cash地址
	cashAddr:=ks.GenCashAddr(MainNet)
	pubKeyHash :=HashPubKey(ks.Pub)
	versionedpayload := append([]byte{version},pubKeyHash...)
	checksum:=checkSum(versionedpayload)
	//将校验码拼接在hash后公钥并添加版本号的后面
	// version + pubKeyHash + checkSum
	fullPayload:= append(versionedpayload,checksum...)
	//进行Base58编码
	leacyAddr := Base58Encode(fullPayload)
	fmt.Println("LegacyAddr: ",string(leacyAddr))
	fmt.Println("CashAddr: ",cashAddr)
}

func (ks *Keystore)GenCashAddr(prefix string)(string){
	//对公钥进行sha256-ripemd160hash
	hash:=ks.hashPubkey()

	out,err:=packAddress(hash,P2KH)
	if err != nil {
		return ""
	}
	//计算checksum
	checksum:=calculateChecksum(MainNet,append(out, 0, 0, 0, 0, 0, 0, 0, 0))

	payload:=appendChecksum(out,checksum)
	//base32编码
	address,err:=Base32Encode(payload)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s:%s",prefix,address)
}
func (ks *Keystore)hashPubkey()[]uint8{
	publicSHA256 :=sha256.Sum256(ks.Pub)
	RIPEMDHasher :=ripemd160.New()
	_,err:=RIPEMDHasher.Write(publicSHA256[:])
	if err != nil {
		fmt.Println("Ripemd160失败",err)
	}
	pubRIPEMD160 :=RIPEMDHasher.Sum(nil)
	return pubRIPEMD160
}

//将8位表示1字节转换位5位表示为1字节
func packAddress(hash []uint8,addrType uint8)([]uint8,error){
	version := uint8(addrType << 3)
	var size uint8
	switch len(hash)*8 {
	case 160:
		size = 0
		break
	case 192:
		size = 1
		break
	case 224:
		size = 2
		break
	case 256:
		size = 3
		break
	case 320:
		size = 4
		break
	case 384:
		size = 5
		break
	case 448:
		size = 6
		break
	case 512:
		size = 7
		break
	default:
		return nil,errors.New("invalid address size")
	}
	version_byte := version | size
	payload:=make([]uint8,0,len(hash)+1)
	payload = append(payload,version_byte)
	payload = append(payload,hash...)
	//payload = version+hash
	//将8位表示法转换为5位表示法
	out,ok:=convertBits(8,5,payload,true)

	if !ok{
		return nil,errors.New("ConvertBits error")
	}
	return out,nil
}

// ConvertBits takes a byte array as `input`, and converts it from `frombits`
// bit representation to a `tobits` bit representation, while optionally
// padding it.  ConvertBits returns the new representation and a bool
// indicating that the output was not truncated.
func convertBits(frombits uint8, tobits uint8, input []uint8, pad bool) ([]uint8, bool) {
	if frombits > 8 {
		return nil, false
	}

	var acc uint64 = 0
	var bits uint64 = 0
	var out []uint8 = make([]uint8, 0, len(input)*int(frombits)/int(tobits))
	var maxv uint64 = (1 << tobits) - 1
	var max_acc uint64 = (1 << (frombits + tobits - 1)) - 1
	for _, d := range input {
		acc = ((acc << uint64(frombits)) | uint64(d)) & max_acc
		bits += uint64(frombits)
		for bits >= uint64(tobits) {
			bits -= uint64(tobits)
			v := (acc >> bits) & maxv
			out = append(out, uint8(v))
		}
	}

	// We have remaining bits to encode but do not pad.
	if !pad && bits > 0 {
		return out, false
	}

	// We have remaining bits to encode so we do pad.
	if pad && bits > 0 {
		out = append(out, uint8((acc<<(uint64(tobits)-bits))&maxv))
	}

	return out, true
}
//取一个8个字节，每个字节5位的字节数组，并与之前的hash合并
//这是bech32编码格式，具体得看bech32
func appendChecksum(packedaddr []uint8, poly uint64) []uint8 {
	chkarr := make([]uint8, 0, 8)
	mod:=poly ^ 1
	var i uint
	for i = 0; i < 8; i++ {
		chkarr = append(chkarr, uint8((mod>>uint(5*(7-i)))&0x1F))
	}
	return append(packedaddr, chkarr...)
}


//bch特有的checksum检验函数
var generator = []uint64{0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470}
func polymod(values []uint8) uint64 {
	chk := uint64(1)
	for _, v := range values {
		top := uint64(chk >> 35)
		chk = ((chk & 0x07ffffffff)<< 5 ) ^uint64(v)
		for i := 0; i < 5; i++ {
			if top &uint64(math.Exp2(float64(i)))  !=0{
				chk ^= generator[i]
			}
		}
	}
	return chk
}
// 对  hrp进行转换
func expandPrefix(prefix string) []uint8 {
	out := make([]uint8, 0, len(prefix)+1)

	for _, r := range prefix {
		// 取每个字符的最右边5位，也就是低5位
		//0x1F二进制位 11111  和任何数 & 都会取到低5位
		out = append(out, uint8(r)&0x1F)

	}
	//最后的分割符（:）为0，即低五位都为0
	out = append(out, 0)
	return out
}
//计算checksum
func calculateChecksum(prefix string, packedaddr []uint8) uint64 {
	exphrp := expandPrefix(prefix)

	combined := append(exphrp, packedaddr...)
	return polymod(combined)
}


