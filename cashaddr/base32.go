package cashaddr

import (
	"bytes"
	"fmt"
	"strings"
)
var charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
func Base32Encode(combined []uint8)(string,error){
	var ret bytes.Buffer
	for idx, p := range combined {
		if p < 0 || int(p) >= len(charset) {
			return "", fmt.Errorf("invalid data : data[%d]=%d", idx, p)
		}
		ret.WriteByte(charset[p])
	}
	return ret.String(),nil
}

func Base32Decode(hrp,bechString string)(uint8, []uint8, error){
	dehrp,data,err:=decode(bechString)
	if err != nil {
		return 0, nil,fmt.Errorf("decode cash address error,Err=【%v】",err)
	}
	if dehrp != hrp {
		return 0, nil, fmt.Errorf("invalid human-readable part : %s != %s", hrp, dehrp)
	}
	out,_:=convertBits(5,8,data[:],false)
	// Ensure there isn't extra non-zero padding
	extrabits := len(out) * 5 % 8
	if extrabits >= 5 {
		return 0, nil,fmt.Errorf("non-zero padding")
	}
	version_byte := int(out[0])
	addrtype := version_byte >> 3
	decoded_size := 20 + 4*(version_byte&0x03)
	if version_byte&0x04 == 0x04 {
		decoded_size = decoded_size * 2
	}
	if decoded_size != len(out)-1 {
		return 0,nil, fmt.Errorf("invalid size information (%v != %v)", decoded_size, len(out)-1)
	}
	return uint8(addrtype),out[1:],nil
}

func decode(bechString string) (string, []uint8, error) {
	if len(bechString) > 90 {
		return "", nil, fmt.Errorf("too long : len=%d", len(bechString))
	}
	if strings.ToLower(bechString) != bechString && strings.ToUpper(bechString) != bechString {
		return "", nil, fmt.Errorf("mixed case")
	}
	bechString = strings.ToLower(bechString)
	pos := strings.LastIndex(bechString, ":")
	if pos < 1 || pos+7 > len(bechString) {
		return "", nil, fmt.Errorf("separator '1' at invalid position : pos=%d , len=%d", pos, len(bechString))
	}
	hrp := bechString[0:pos]
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, fmt.Errorf("invalid character human-readable part : bechString[%d]=%d", p, c)
		}
	}
	data := []uint8{}
	for p := pos + 1; p < len(bechString); p++ {
		d := strings.Index(charset, fmt.Sprintf("%c", bechString[p]))
		if d == -1 {
			return "", nil, fmt.Errorf("invalid character data part : bechString[%d]=%d", p, bechString[p])
		}
		data = append(data, uint8(d))
	}
	if !verifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("invalid checksum")
	}
	//checksum是8个字节，剪掉
	return hrp, data[:len(data)-8], nil
}
func verifyChecksum(hrp string, data []uint8) bool {
	return polymod(append(expandPrefix(hrp), data...)) == 1
}