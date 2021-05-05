package ethutil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

//签名
type Signature struct {
	R []byte
	S []byte
	V uint8
}

type AbiParam struct {
	Type string
	Data []byte
}

//获取签名地址
func Ecrecover(digestHash []byte, signature []byte) string {
	bs, err := secp256k1.RecoverPubkey(digestHash, signature)
	if err != nil {
		panic(err)
	}

	return hexutil.Encode(bs)
}

//签名消息 The produced signature is in the [R || S || V] format where V is 0 or 1.
func SignMessage(digestHash []byte, prv *ecdsa.PrivateKey) *Signature {
	bs, err := crypto.Sign(digestHash, prv)
	if err != nil {
		panic(err)
	}

	return &Signature{
		R: bs[0:32],
		S: bs[32:64],
		V: bs[64] + 27,
	}
}

//验证签名
func VerifySignature(address string, digestHash, signature []byte) bool {
	return secp256k1.VerifySignature(common.FromHex(address), digestHash, signature)
}

//16进制字符串转换为签名
func ExtractEcdsaSignature(signHex string) *Signature {
	r, _ := hex.DecodeString(signHex[0:64])
	s, _ := hex.DecodeString(signHex[64:128])
	v, _ := hex.DecodeString(signHex[128:])

	return &Signature{
		//*(*[32]byte)((*stringStruct)(unsafe.Pointer(&r)).str)
		R: r,
		S: s,
		V: v[0],
	}
}

//将签名转换为16进制字符串
func JoinSignature(sign *Signature) string {
	return hex.EncodeToString(bytes.Join([][]byte{sign.R[:], sign.S[:], {sign.V}}, []byte("")))
}

//计算数据的Keccak256值
func Keccak256(data []byte) []byte {
	return crypto.Keccak256(data)
}

//签名原始参数
func SignOriginDatas(prv *ecdsa.PrivateKey, prefix []byte, params *[]AbiParam) *Signature {

	packedBytes := append(prefix, crypto.Keccak256(*PackSignArgs(params))...)
	msgHash := crypto.Keccak256(packedBytes)

	return SignMessage(msgHash, prv)
}

func CalcSignVByChainId(chainID *big.Int, v uint8) int64 {
	cid, err := strconv.ParseInt(chainID.String(), 10, 64)
	if err != nil {
		panic(err)
	}

	return int64(v) + 35 + cid*2
}

//还原签名中的V,总是返回0||1
func RestoreSignV(chainID *big.Int, v int64) uint8 {
	var res uint8
	if chainID.Sign() != 0 {
		cid, err := strconv.ParseInt(chainID.String(), 10, 64)
		if err != nil {
			panic(err)
		}
		res = uint8(v - 35 - cid*2)
		//res+=27
	}

	return res
}

// deriveChainId derives the chain id from the given v parameter
func DeriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}

//根据私钥获取地址
func GetAddress(privateKey string) string {
	k, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		panic(err)
	}

	return strings.ToLower(crypto.PubkeyToAddress(k.PublicKey).Hex())
}

func PubkeyToAddress(pubkey *ecdsa.PublicKey) string {
	return strings.ToLower(crypto.PubkeyToAddress(*pubkey).Hex())
}

func HexToAddress(addr string) common.Address {
	return common.FromHex(addr)
}

func AddressToHex(addr common.Address) string {
	return addr.Hex()
}

func HexToBytes(hexStr string) []byte {
	bs, err := hexutil.Decode(hexStr)
	if err != nil {
		panic(err)
	}

	return bs
}

func BytesToHex(buf []byte) string {
	return hexutil.Encode(buf)
}

//私钥字符串转ecdsa私钥指针
func HexToECDSAPrivateKey(privateKey string) *ecdsa.PrivateKey {
	p, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		panic(err)
	}

	return p
}

//ecdsa私钥指针转私钥字符串
func ECDSAPrivateKeyToHex(prv *ecdsa.PrivateKey) string {
	return hexutil.Encode(crypto.FromECDSA(prv))
}

//是否是有效的私钥16进制字符串
func IsValidPrivateKeyHex(hex string) bool {
	hexBytes, err := hexutil.Decode(hex)
	return err == nil && len(hexBytes) == 32
}

//判断是否是有效的地址16进制字符串
func IsValidAddressHex(hex string) bool {
	return common.IsHexAddress(hex)
}

//将16进制字符串转换为eth标准的16进制形式字符串（统一小写）
func GetEthStandardHex(hex string) string {
	s := strings.ToLower(hex)
	if s[0:2] == "0x" {
		return s
	} else {
		return "0x" + s
	}
}

//打包签名用的参数
func PackSignArgs(datas *[]AbiParam) *[]byte {
	var buf []byte
	for _, d := range *datas {
		if len(d.Data) >= 32 || d.Type == "string" {
			buf = append(buf, d.Data...)
		} else {
			buf = append(buf, append(make([]byte, 32-len(d.Data)), d.Data...)...)
		}
	}

	return &buf
}

//打包调用合约方法用的参数
func PackFuncArgs(datas *[]AbiParam) *[]byte {
	var buf []byte
	for _, d := range *datas {
		if d.Type == "string" {
			lenBytes := append(make([]byte, 24), Int64ToBytes(int64(len(d.Data)))...)
			buf = append(buf, lenBytes...)
			buf = append(buf, d.Data...)
		} else if len(d.Data) < 32 {
			buf = append(buf, append(make([]byte, 32-len(d.Data)), d.Data...)...)
		} else {
			buf = append(buf, d.Data...)
		}
	}

	return &buf
}

//签名交易
func SignTx(prv *ecdsa.PrivateKey, tx *types.Transaction, chainID *big.Int) *types.Transaction {
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), prv)
	if err != nil {
		panic(err)
	}

	return signedTx
}

//发送已签名的tx
func SendRawTx(client *ethclient.Client, tx *types.Transaction) error {
	return client.SendTransaction(context.Background(), tx)
}

//获取已签名交易的txhash
func GetRawTxHash(tx *types.Transaction) string {
	return tx.Hash().Hex()
}

//获取合约abi对象
func GetContractAbi(abiJson string) *abi.ABI {
	abiObj, err := abi.JSON(strings.NewReader(abiJson))
	if err != nil {
		panic(err)
	}

	return &abiObj
}

//生成新交易（未签名）
func NewTx(nonce uint64, to string, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
	var toAddr common.Address
	if strings.Trim(to, " ") == "" {
		toAddr = nil
	} else {
		toAddr = common.HexToAddress(to)
	}
	return types.NewTransaction(nonce, toAddr, amount, gasLimit, gasPrice, data)
}

//获取交易from地址
func GetTxFrom(tx *types.Transaction, chainID *big.Int) string {
	addr, err := types.NewEIP155Signer(chainID).Sender(tx)
	if err != nil {
		panic(err)
	}

	return addr.Hex()
}

func Int64ToBytes(i int64) []byte {
	s1 := make([]byte, 8)
	binary.BigEndian.PutUint64(s1, uint64(i))
	return s1
}

func Int32ToBytes(i int64) []byte {
	s1 := make([]byte, 4)
	binary.BigEndian.PutUint32(s1, uint32(i))
	return s1
}

func IntToBytes(i int) []byte {
	s1 := make([]byte, 8)
	binary.BigEndian.PutUint64(s1, uint64(i))
	return s1
}

func GetInfuraEthClientUseSecret(endpoint string, secret string) (*ethclient.Client, error) {
	return GetEthClientWithHeader(endpoint, "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+secret)))
}

func GetInfuraEthClientUseJWT(endpoint string, token string) (*ethclient.Client, error) {
	return GetEthClientWithHeader(endpoint, "Authorization", "Bearer "+token)
}

func GetEthClientWithHeader(endpoint string, key string, val string) (*ethclient.Client, error) {
	rpcClient, err := rpc.Dial(endpoint)
	if err != nil {
		return nil, err
	}
	rpcClient.SetHeader(key, val)

	return ethclient.NewClient(rpcClient), nil
}

func Add0xPrefix(hexStr string) string {
	if len(hexStr) >= 2 && hexStr[0] == '0' && (hexStr[1] == 'x' || hexStr[1] == 'X') {
		return strings.ToLower(hexStr)
	} else {
		return "0x" + strings.ToLower(hexStr)
	}
}
