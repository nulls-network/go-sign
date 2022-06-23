package main

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

func main() {
	order := Order{
		notify:"http://localhost",
		out_order_no:"c8b8893f-3532-4283-91bb-edddd0d7",
		pay_amount:"0.01",
		pay_chain:"tron",
		pay_token:"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
		pub_key:"0x2143d11b31b319c008f59c2d967ebf0e5ad2791d",
		signature:"0xa1d57164520dd4a03c2b733dd13aa229ba6c19d7235a00815a0d08929f977ed738386f25196c9a303af25f3040177975db2dc6d9658196b454dda0c49cf6cd5e1b",
		version:"1.0",
	}
	sign(order, "f78494eb224f875d7e352a2b017304e11e6a3ce94af57b373ae82a73b3496cdd")


	testRecoverNotify()
}





func sign(order Order,privateKeyStr string){
	privateKey, err := crypto.HexToECDSA(privateKeyStr)
	if err != nil {
		log.Fatal(err)
	}
	hash := crypto.Keccak256Hash(order.getBytes())
	hashByte := []byte(hash.Hex())
	//length := hash.Bytes()
	//fmt.Print(length)
	var a string = "\x19Ethereum Signed Message:\n66"
	header := []byte(a)
	bytes := BytesCombine(header, hashByte)
	hash = crypto.Keccak256Hash(bytes)
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	signature[len(signature) - 1] += 27
	fmt.Println(hexutil.Encode(signature)) // 0x789a80053e4927d0a898db8e065e948f5cf086e32f9ccaa54c1908e22ac430c62621578113ddbb62d509bf6049b8fb544ab06d36f916685a2eb8e57ffadde02301

	recover(hash.Bytes(), hexutil.Encode(signature))
}

func recover(hashBytes []byte, signature string) {
	signBytes, err := hexutil.Decode(signature)
	signBytes[len(signBytes) - 1] -= 27
	sigPublicKeyECDSA, err := crypto.SigToPub(hashBytes, signBytes)
	if err != nil {
		log.Fatal(err)
	}

	signAddress := crypto.PubkeyToAddress(*sigPublicKeyECDSA).Hex()
	fmt.Println(signAddress)
}


func testRecoverNotify() {
	notify := Notify{
			out_order_no: "1652342887226",
			uuid: "aa24f0a5-c8e2-45da-a062-05693b0112b7",
			merchant_address: "0x8cf6F24dddb965e6636d46129f28050c3357c43b",
			_type: "recharge",
			amount: "0.0100",
			amount_hex: "10000",
			got_amount: "0.0100",
			pay_result: "success",
			token: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
			bind_uuid: "10925df6-221c-44ab-905f-df5e48697815",
			user_id: "5261807812",
			sign: "0xdf26ba7ff8d6933bbe63271b9d266440c63cb630676a2c05a55fc72f7d639ae62af7125bef4fea1df29983652d8b934d72602f971fb66591a080daf786ecdb4e1b",

	}
	getBytes := notify.getBytes()
	hash := crypto.Keccak256Hash(getBytes)
	recover(hash.Bytes(), notify.sign)
}


type Sign interface {
	getBytes() []byte
}

type Order struct {
	out_order_no string
	pay_chain string
	pay_token string
	pay_amount string
	signature string
	notify string
	pub_key string
	version string
}

type Notify struct {
	out_order_no string
	uuid string
	merchant_address string
	_type string
	amount string
	amount_hex string
	got_amount string
	pay_result string
	token string
	bind_uuid string
	user_id string
	sign string
}

func (order Order) getBytes() []byte {
	out_order_no := []byte(order.out_order_no)
	pay_chain := []byte(order.pay_chain)
	pay_token := []byte(order.pay_token)
	pay_amount := []byte(order.pay_amount)
	notify := []byte(order.notify)

	return BytesCombine(out_order_no,pay_chain,pay_token,pay_amount,notify)
}

func (notify Notify) getBytes() []byte {
	out_order_no := []byte(notify.out_order_no)
	uuid := []byte(notify.uuid)
	merchant_address := []byte(notify.merchant_address)
	_type := []byte(notify._type)
	amount := []byte(notify.amount)
	amount_hex := []byte(notify.amount_hex)
	got_amount := []byte(notify.got_amount)
	pay_result := []byte(notify.pay_result)
	token := []byte(notify.token)
	bind_uuid := []byte(notify.bind_uuid)
	user_id := []byte(notify.user_id)

	if notify._type == "recharge" {
		return BytesCombine(out_order_no, uuid, merchant_address, _type, amount, amount_hex, got_amount, pay_result, token, bind_uuid, user_id)
	} else {
		return BytesCombine(out_order_no, uuid, merchant_address, _type, amount, amount_hex, got_amount, pay_result, token)
	}

}



func BytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}
