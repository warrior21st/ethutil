package ethutil

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type TxBaseParams struct {
	chainId  *big.Int
	nonce    uint64
	gas      uint64
	gasPrice *big.Int
}

func getNextNonce(client *ethclient.Client, account string) uint64 {
	nonce, err := client.NonceAt(context.Background(), common.HexToAddress(account), big.NewInt(rpc.LatestBlockNumber.Int64()))
	for err != nil {
		logWithTime(fmt.Sprintf("get %s nonce err: %s,sleep 1s...", account, err.Error()))
		time.Sleep(time.Second)

		nonce, err = client.NonceAt(context.Background(), common.HexToAddress(account), big.NewInt(rpc.LatestBlockNumber.Int64()))
	}
	logWithTime(fmt.Sprintf("%s next nonce: %d", account, nonce))

	return nonce
}

func waitTxReceipt(client *ethclient.Client, txId string, txDesc string, maxQuerySeconds int64) bool {
	timeStart := time.Now().UnixMilli()
	for true {
		receipt, err := client.TransactionReceipt(context.Background(), common.HexToHash(txId))
		if receipt == nil {
			if err == nil {
				logWithTime(fmt.Sprintf("waiting %s tx %s confirming...", txDesc, txId))
			} else {
				logWithTime(fmt.Sprintf("get %s tx %s receipt err: %s...", txDesc, txId, err.Error()))
			}
			time.Sleep(time.Duration(3) * time.Second)
		} else {
			if receipt.Status == 1 {
				break
			} else {
				logWithTime(txDesc + " tx exec failed")
				return false
			}
		}
		if time.Now().UnixMilli()-timeStart >= maxQuerySeconds {
			logWithTime(fmt.Sprintf("get receipt of tx %s time out", txId))
			return false
		}
	}

	return true
}

func logWithTime(msg string) {
	fmt.Printf("%s %s\n", time.Now().UTC().Add(8*time.Hour).Format("2006-01-02 15:04:05"), msg)
}
