package tokenutil

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/warrior21st/ethutil"
)

const (
	ERC20Abi                = `[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]`
	ApproveERC20DefaultGas  = 60000
	TransferERC20DefaultGas = 60000
)

func Name(client *ethclient.Client, token string) (string, error) {
	result, err := erc20Call(client, token, "name")
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func Symbol(client *ethclient.Client, token string) (string, error) {
	result, err := erc20Call(client, token, "symbol")
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func Decimals(client *ethclient.Client, token string) (int64, error) {
	result, err := erc20Call(client, token, "decimals")
	if err != nil {
		return 0, err
	}

	return big.NewInt(0).SetBytes(result).Int64(), nil
}

func TotalSupply(client *ethclient.Client, token string) (*big.Int, error) {
	result, err := erc20Call(client, token, "totalSupply")
	if err != nil {
		return nil, err
	}

	return big.NewInt(0).SetBytes(result), nil
}

func BalanceOf(client *ethclient.Client, token string, account string) (*big.Int, error) {
	result, err := erc20Call(client, token, "balanceOf", common.HexToAddress(account))
	if err != nil {
		return nil, err
	}

	return big.NewInt(0).SetBytes(result), nil
}

func Allowance(client *ethclient.Client, token string, owner string, spender string) (*big.Int, error) {
	result, err := erc20Call(client, token, "allowance", common.HexToAddress(owner), common.HexToAddress(spender))
	if err != nil {
		return nil, err
	}

	return big.NewInt(0).SetBytes(result), nil
}

func erc20Call(client *ethclient.Client, token string, method string, args ...interface{}) ([]byte, error) {
	contract := ethutil.GetContractAbi(ERC20Abi)
	callData, err := contract.Pack(method, args...)
	if err != nil {
		return nil, err
	}

	contractAddr := common.HexToAddress(token)
	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: callData,
	}, big.NewInt(rpc.LatestBlockNumber.Int64()))

	if err != nil {
		return nil, err
	}

	return result, nil
}

func erc20Send(client *ethclient.Client, chainId *big.Int, priv *ecdsa.PrivateKey, token string, method string, nonce uint64, gas uint64, gasPrice *big.Int, args ...interface{}) (string, error) {
	contract := ethutil.GetContractAbi(ERC20Abi)

	inputData, err := contract.Pack(method, args...)
	if err != nil {
		return "", err
	}

	tx := ethutil.NewTx(nonce, token, big.NewInt(0), gas, gasPrice, inputData)
	signedTx := ethutil.SignTx(priv, tx, chainId)
	txId := ethutil.GetRawTxHash(signedTx)
	ethutil.SendRawTx(client, signedTx)

	return txId, nil
}

func Approve(client *ethclient.Client, chainId *big.Int, priv *ecdsa.PrivateKey, token string, to string, nonce uint64, gas uint64, gasPrice *big.Int) (string, error) {
	bi := big.NewInt(2)
	bi.Exp(bi, big.NewInt(256), nil)
	bi.Sub(bi, big.NewInt(1))

	return erc20Send(client, chainId, priv, token, "approve", nonce, gas, gasPrice)
}

func Transfer(client *ethclient.Client, priv *ecdsa.PrivateKey, token string, to string, nonce uint64, gas int64, gasPrice *big.Int) (string, error) {
	erc20ContractAbi := ethutil.GetContractAbi(ERC20Abi)
	transferAmount := big.NewInt(0).Mul(big.NewInt(100), big.NewInt(1e18))

	inputData, err := erc20ContractAbi.Pack("transfer", common.HexToAddress(to), transferAmount)
	if err != nil {
		return "", err
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return "", err
	}

	tx := ethutil.NewTx(nonce, token, big.NewInt(0), uint64(gas), gasPrice, inputData)
	signedTx := ethutil.SignTx(priv, tx, chainId)
	txId := ethutil.GetRawTxHash(signedTx)
	ethutil.SendRawTx(client, signedTx)

	return txId, nil
}

func logWithTime(msg string) {
	fmt.Printf("%s %s\n", time.Now().UTC().Add(8*time.Hour).Format("2006-01-02 15:04:05"), msg)
}
