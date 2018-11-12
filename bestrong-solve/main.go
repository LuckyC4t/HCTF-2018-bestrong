package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"bestrong-solve/jose2go-change"
	"bestrong-solve/jose2go-change/base64url"
	"bestrong-solve/jose2go-change/keys/ecc"
)

func main() {
	//KRsLupcReArgT_4kyJ9nmoWWB_yDysEVe1GpIHJyOrM= VXUvu8OSgP_1qhamS2lpT0-Sc_sCRxMVd0013Fmtens= 487
	//YIjKIpNuWJep9NmKJ0WMh8vZSrY94vf_olOMm7mu6E8= EbC6quNbMTmbxTIjVgNYOTRGYIaHzj2W8bRIQ5F29Zg= 1049
	//rISJ58HQZrH8MLWNG2IUfTG1-PxNnbLqVWohrdKgrck= Y5glbzWYzAC_5D2qGIfS5_6874INZTHFkLHWhJ4R4L4= 1439
	//H5x5EX4qLjzu5vlpA02V3M5Yk_9C8nJSvJG2_D-GCD0= zze5V2I-EKkYrxJxyxz6vGEvBnS6nrSy7fbmCetByCI= 443
	//sJAKnU50ZiSx_cb3jiVqC7Ow-tF1w44IPRI0ZiUriG8= 5PBZUKHVNgEdd6BTQnEYj5G5vnwpBpZ1i0wBNAnBcx0= 101
	url := "http://bestrong.2018.hctf.io"
	session := "MTU0MTgzMTg1OXxOd3dBTkZGU1QwVTBUVlZPVUVOSU5qWk9RVFJRUVRRMlRWVkZWRlkyVmxWR1RUVlBWRWRIVmtwVE5rOVNORkJNVUV3MFJVaFdURUU9fOQ_cPWFe910i0Q0362VmkzI1X7yST6kHMaCGjHYUz88"
	point := map[string]int {
		"KRsLupcReArgT_4kyJ9nmoWWB_yDysEVe1GpIHJyOrM=|VXUvu8OSgP_1qhamS2lpT0-Sc_sCRxMVd0013Fmtens=":487,
		"YIjKIpNuWJep9NmKJ0WMh8vZSrY94vf_olOMm7mu6E8=|EbC6quNbMTmbxTIjVgNYOTRGYIaHzj2W8bRIQ5F29Zg=":1049,
		"rISJ58HQZrH8MLWNG2IUfTG1-PxNnbLqVWohrdKgrck=|Y5glbzWYzAC_5D2qGIfS5_6874INZTHFkLHWhJ4R4L4=":1439,
		"H5x5EX4qLjzu5vlpA02V3M5Yk_9C8nJSvJG2_D-GCD0=|zze5V2I-EKkYrxJxyxz6vGEvBnS6nrSy7fbmCetByCI=":443,
		"sJAKnU50ZiSx_cb3jiVqC7Ow-tF1w44IPRI0ZiUriG8=|5PBZUKHVNgEdd6BTQnEYj5G5vnwpBpZ1i0wBNAnBcx0=":101,
	}
	k := map[int][]int{}
	for p, order := range point {
		x, _ := base64url.Decode(strings.Split(p, "|")[0])
		y, _ := base64url.Decode(strings.Split(p, "|")[1])
		for i := 1; i < order; i++ {
			var d = make([]byte, 8)
			client := &http.Client{}
			binary.BigEndian.PutUint64(d, uint64(i))
			pk := ecc.NewPrivate(x, y, d)
			payload := "xxxxxx"
			token, err := jose.Encrypt(payload, jose.ECDH_ES_A256KW, jose.A256CBC_HS512, pk.Public(), pk)
			if err == nil {
				req, err := http.NewRequest("GET", url+"/hello/alice", nil)
				if err != nil {
					log.Fatal(err)
				}
				req.Header.Add("Cookie", "session="+session+"; token="+token)
				response, _ := client.Do(req)
				defer response.Body.Close()
				body, _ := ioutil.ReadAll(response.Body)
				if bytes.Contains(body, []byte("bob")) {
					fmt.Println(order,":",i)
					k[order] = append(k[order],i)
				}
			}
		}
	}
	p := [][]int{}
	for _,a := range k[487] {
		for _,b := range k[1049] {
			for _,c := range k[1439] {
				for _,d := range k[443] {
					for _,e := range k[101] {
						p = append(p,[]int{a,b,c,d,e})
					}
				}
			}
		}
	}
	d := []uint64{}
	for _, i := range p {
		d = append(d, crt(i,[]int{487,1049,1439,443,101}))
	}
	getflag(d,session, url)
}

func getflag(D []uint64, session string, url string) {
	type key struct {
		X    string
		Y    string
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", url+"/alice", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Cookie", "session="+session)
	response, _ := client.Do(req)
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	var a key
	json.Unmarshal(body, &a)
	for _, pd := range D {
		px, _ := base64url.Decode(a.X)
		py, _ := base64url.Decode(a.Y)
		var d = make([]byte, 8)
		client := &http.Client{}
		binary.BigEndian.PutUint64(d, pd)
		pk := ecc.NewPrivate(px, py, d)
		payload := "xxxxxx"
		token, err := jose.Encrypt(payload, jose.ECDH_ES_A256KW, jose.A256CBC_HS512, publicKey(session, url), pk)
		if err == nil {
			req, err := http.NewRequest("GET", url+"/hello/bob", nil)
			if err != nil {
				log.Fatal(err)
			}
			req.Header.Add("Cookie", "session="+session+"; token="+token)
			response, _ := client.Do(req)
			defer response.Body.Close()
			body, _ := ioutil.ReadAll(response.Body)
			fmt.Println(string(body))
		}
	}
}


func publicKey(session, url string) *ecdsa.PublicKey {
	type key struct {
		X    string
		Y    string
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", url+"/bob", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Cookie", "session="+session)
	response, _ := client.Do(req)
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	var a key
	json.Unmarshal(body, &a)

	x, _ := base64url.Decode(a.X)
	y, _ := base64url.Decode(a.Y)
	return ecc.NewPublic(x, y)
}

func egcd(a, b int) (int, int, int){
	if a == 0 {
		return b, 0, 1
	} else {
		g, y, x := egcd(b%a, a)
		return g, x - (b/a)*y, y
	}
}
func modinv(a, m int) int {
	g, x, _ := egcd(a, m)
	if g != 1 {
		return 0
	} else {
		if x < 0 {
			x += m
		}
		return x % m
	}
}

func crt(c, n []int) uint64 {
	l := len(n)
	var N int
	N = 1
	for _, i := range n {
		N *= i
	}
	Ni := []int{}
	for _, i := range n {
		Ni = append(Ni, N/i)
	}
	T := []int{}
	for i := 0; i < l; i++ {
		T = append(T, modinv(Ni[i], n[i]))
	}
	var X int
	X = 0
	for i := 0; i < l; i++ {
		X += c[i] * Ni[i] * T[i]
	}
	return uint64(X-(X/N)*N)
}