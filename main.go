// Copyright 2020 The TOTP Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"
)

// Token is a TOTP token
type Token struct {
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	Counter   float64   `json:"counter"`
	Digits    float64   `json:"digits"`
	Period    float64   `json:"period"`
	Secret    []float64 `json:"secret"`
}

func truncate(in []byte) int64 {
	offset := int(in[len(in)-1] & 0xF)
	p := in[offset : offset+4]
	var binCode int32
	binCode = int32((p[0] & 0x7f)) << 24
	binCode += int32((p[1] & 0xff)) << 16
	binCode += int32((p[2] & 0xff)) << 8
	binCode += int32((p[3] & 0xff))
	return int64(binCode) & 0x7FFFFFFF
}

func main() {
	data, err := ioutil.ReadFile("token.json")
	if err != nil {
		panic(err)
	}

	token := Token{}
	err = json.Unmarshal(data, &token)
	if err != nil {
		panic(err)
	}

	key := make([]byte, len(token.Secret))
	for i, v := range token.Secret {
		key[i] = byte(int8(v))
	}

	h := hmac.New(sha1.New, key)
	c := (time.Now().Unix() - int64(token.Counter)) / int64(token.Period)
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(c))
	h.Write(counter)
	hash := h.Sum(nil)
	result := truncate(hash)

	mod := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(token.Digits)), nil)
	mod = mod.Mod(big.NewInt(result), mod)
	fmtStr := fmt.Sprintf("%%0%dd\n", int64(token.Digits))
	fmt.Printf(fmtStr, mod.Uint64())
}
