package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type TokenConfig struct {
	AuthTokenURL    string `json:"authTokenURL"`
	APIKey          string `json:"apiKey"`
	Base64PublicKey string `json:"base64PublicKey"`
}

type TokenUtils struct {
	config    TokenConfig
	publicKey *rsa.PublicKey
}

type TokenResponse struct {
	Code int    `json:"code"`
	Data string `json:"data"`
}

func NewTokenUtils(cfg TokenConfig) *TokenUtils {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.Base64PublicKey)
	if err != nil {
		panic("无法解码Base64公钥")
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		panic("无法解析公钥")
	}
	publicKey := pubKey.(*rsa.PublicKey)

	return &TokenUtils{
		config:    cfg,
		publicKey: publicKey,
	}
}

func (tu *TokenUtils) GetToken() (string, error) {
	encrypted, err := tu.rsaEncrypt([]byte(strconv.FormatInt(time.Now().UnixNano()/1000000, 10)))
	if err != nil {
		return "", err
	}

	data := map[string]string{
		"apiKey":    tu.config.APIKey,
		"encrypted": base64.StdEncoding.EncodeToString(encrypted),
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(tu.config.AuthTokenURL, "application/json", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.Data, nil
}

func (tu *TokenUtils) rsaEncrypt(plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, tu.publicKey, plaintext)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
