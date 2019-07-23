package cashaddr

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
	"math/big"
)

/*
原来的地址
*/
const version = byte(0x00)
const addressCheckSumLen = 4

//对公钥进行 sha256 和 ripemd160  Hash
func HashPubKey(pubKey []byte) []byte{
	publicSHA256 :=sha256.Sum256(pubKey)
	RIPEMDHasher :=ripemd160.New()
	_,err:=RIPEMDHasher.Write(publicSHA256[:])
	if err != nil {
		fmt.Println("Ripemd160失败",err)
	}
	pubRIPEMD160 :=RIPEMDHasher.Sum(nil)
	return pubRIPEMD160
}
//对  版本号+公钥Hash值进行校验  返回校验值
func checkSum(payload []byte)[]byte {
	//双sha256
	firstSHA :=sha256.Sum256(payload)
	secondSHA :=sha256.Sum256(firstSHA[:])
	return secondSHA[:addressCheckSumLen] //获取16进制前四个字节
}


//test
var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// 将字节数组编码成base58格式
func Base58Encode(input []byte)[]byte{
	var result []byte
	x:=big.NewInt(0).SetBytes(input)
	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}
	for x.Cmp(zero) !=0{
		x.DivMod(x,base,mod)
		result = append(result,b58Alphabet[mod.Int64()])
	}
	ReverseBytes(result)
	for b :=range input{
		if b==0x00{
			result=append([]byte{b58Alphabet[0]},result...)
		}else {
			break
		}
	}
	return result
}

// base58 解码
func Base58Decode(input []byte)[]byte{
	result :=big.NewInt(0)
	zeroBytes :=0
	for b :=range input{
		if b ==0x00{
			zeroBytes++
		}
	}
	payload :=input[zeroBytes:]
	for _,b :=range payload{
		charIndex :=bytes.IndexByte(b58Alphabet,b)
		result.Mul(result,big.NewInt(58))
		result.Add(result,big.NewInt(int64(charIndex)))
	}
	decoded:= result.Bytes()
	decoded = append(bytes.Repeat([]byte{byte(0x00)},zeroBytes),decoded...)
	return decoded
}
func ReverseBytes(data []byte){
	for i,j :=0,len(data)-1;i<j;i,j=i+1,j-1{
		data[i],data[j]=data[j],data[i]
	}
}


//------test Base58Decode
func testBase58Decode(input [] byte){
	hash:= Base58Decode(input)
	puKeyHash := hash[1:len(hash)-4]
	fmt.Println("解码后的公钥",puKeyHash)
}