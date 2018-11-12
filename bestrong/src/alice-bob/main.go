package main

import (
	"alice-bob/getKek"
	"alice-bob/jose2go"
	"alice-bob/jose2go/base64url"
	"alice-bob/jose2go/keys/ecc"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/location"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/gobuffalo/packr"
	"github.com/gorilla/securecookie"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
)

func main() {
	gob.Register(&Key{})

	gin.DisableConsoleColor()
	f, _ := os.Create("/tmp/gin.log")
	gin.DefaultWriter = io.MultiWriter(f)

	gin.SetMode(gin.ReleaseMode)
	route := gin.Default()

	staticBox := packr.NewBox("./static")
	route.StaticFS("/static", staticBox)

	store, _ := redis.NewStore(1024, "tcp", "localhost:6379", "38c7d2621b39bae1dc4c", securecookie.GenerateRandomKey(32))
	route.Use(sessions.Sessions("session", store))
	route.Use(location.Default())

	route.GET("/", index)
	route.GET("/robots.txt", robots)
	route.GET("/alice", alice)
	route.GET("/bob", bob)
	route.POST("/send", sendMsg)
	route.GET("/hello/:name", hello)
	route.GET("/givemetoken", getTeamToken)
	route.POST("/givemetoken", setTeamToken)

	route.Run(":8085")
}

type Key map[string][]byte

func index(c *gin.Context) {
	session := sessions.Default(c)
	if token := session.Get("token"); token == nil {
		c.Redirect(http.StatusMovedPermanently, "/givemetoken")
		return
	}
	var alice Key
	var bob Key
	a := session.Get("alice")
	b := session.Get("bob")
	if a == nil || b == nil {
		ap, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.String(http.StatusOK, "oops")
			return
		}
		ap.D, err = get32D()
		if err != nil {
			c.String(http.StatusOK, "ooops")
			return
		}
		ap.PublicKey.X, ap.PublicKey.Y = ap.Curve.ScalarBaseMult(ap.D.Bytes())

		alice = Key{
			"x": ap.PublicKey.X.Bytes(),
			"y": ap.PublicKey.Y.Bytes(),
			"d": ap.D.Bytes(),
		}
		bp, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.String(http.StatusOK, "oooops")
			return
		}
		bp.D, err = get32D()
		if err != nil {
			c.String(http.StatusOK, "ooooops")
			return
		}
		bp.PublicKey.X, bp.PublicKey.Y = bp.Curve.ScalarBaseMult(bp.D.Bytes())

		bob = Key{
			"x": bp.PublicKey.X.Bytes(),
			"y": bp.PublicKey.Y.Bytes(),
			"d": bp.D.Bytes(),
		}
		kek := getKek.DeriveKey(ap.Public().(*ecdsa.PublicKey), bp, 256, "ECDH-ES+A256KW")
		session.Set("kek", kek)
		session.Set("alice", alice)
		session.Set("bob", bob)
		session.Set("count", 0)
		session.Save()
	}

	front := packr.NewBox("./templates")
	c.Status(http.StatusOK)
	c.Header("Content-Type","text/html; charset=UTF-8")
	c.Writer.Write(front.Bytes("index.tmpl"))
}

func getTeamToken(c *gin.Context) {
	session := sessions.Default(c)
	if tk := session.Get("token"); tk == nil {
		front := packr.NewBox("./templates")
		c.Status(http.StatusOK)
		c.Header("Content-Type","text/html; charset=UTF-8")
		c.Writer.Write(front.Bytes("givemetoken.tmpl"))
	} else {
		c.Redirect(http.StatusMovedPermanently, "/")
	}
}

func setTeamToken(c *gin.Context) {
	session := sessions.Default(c)
	if tk := session.Get("token"); tk == nil {
		token := c.PostForm("token")
		type apiResp struct {
			Status string
		}
		resp, err := http.Get("https://hctf.io/API/token/"+token)
		if err != nil {
			c.String(http.StatusOK, "network error")
			return
		}
		if resp.StatusCode != 200 {
			c.String(http.StatusOK, "check your team token")
			return
		}
		var status apiResp
		body, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(body, &status)
		if status.Status == "success" {
			session.Set("token", token)
			session.Save()
		} else {
			c.String(http.StatusOK, "check your team token")
			return
		}
		c.Redirect(http.StatusMovedPermanently, "/")
	}
}

func alice(c *gin.Context) {
	session := sessions.Default(c)
	if token := session.Get("token"); token == nil {
		c.Redirect(http.StatusMovedPermanently, "/givemetoken")
		return
	}
	var alice *Key
	a := session.Get("alice")
	if a == nil {
		session.Set("alice", nil)
		session.Set("bob", nil)
		session.Set("kek", nil)
		session.Set("count", 0)
		session.Save()
		c.Redirect(http.StatusMovedPermanently, "/")
		return
	}

	alice = a.(*Key)

	p := ecc.NewPublic((*alice)["x"], (*alice)["y"])
	epk := map[string]string{
		"kty": "EC",
		"x":   base64url.Encode(p.X.Bytes()),
		"y":   base64url.Encode(p.Y.Bytes()),
		"crv": name(p.Curve),
	}
	c.JSONP(http.StatusOK, epk)
}

func bob(c *gin.Context) {
	session := sessions.Default(c)
	if token := session.Get("token"); token == nil {
		c.Redirect(http.StatusMovedPermanently, "/givemetoken")
		return
	}
	var bob *Key
	b := session.Get("bob")
	if b == nil {
		session.Set("alice", nil)
		session.Set("bob", nil)
		session.Set("kek", nil)
		session.Set("count", 0)
		session.Save()
		c.Redirect(http.StatusMovedPermanently, "/")
		return
	}

	bob = b.(*Key)

	p := ecc.NewPublic((*bob)["x"], (*bob)["y"])
	epk := map[string]string{
		"kty": "EC",
		"x":   base64url.Encode(p.X.Bytes()),
		"y":   base64url.Encode(p.Y.Bytes()),
		"crv": name(p.Curve),
	}
	c.JSONP(http.StatusOK, epk)
}

func sendMsg(c *gin.Context) {
	session := sessions.Default(c)
	if token := session.Get("token"); token == nil {
		c.Redirect(http.StatusMovedPermanently, "/givemetoken")
		return
	}
	a := session.Get("alice")
	b := session.Get("bob")
	if a == nil || b == nil {
		c.Redirect(http.StatusMovedPermanently, "/")
		return
	}
	name := c.PostForm("name")
	mes := c.PostForm("message")
	if len([]rune(mes)) >= 140 {
		mes = mes[:140]
	}

	url := location.Get(c)

	switch name {
	case "alice":
		alice := a.(*Key)
		p := ecc.NewPublic((*alice)["x"], (*alice)["y"])
		jwt, err := jose.Encrypt(mes, jose.ECDH_ES_A256KW, jose.A256CBC_HS512, p)

		if err != nil {
			c.String(http.StatusOK, "oooooops")
			return
		}
		c.SetCookie("token", jwt, 3600, "/", url.Hostname(), false, true)
		c.String(http.StatusOK, "have good time with alice")
	case "bob":
		bob := b.(*Key)
		p := ecc.NewPublic((*bob)["x"], (*bob)["y"])
		jwt, err := jose.Encrypt(mes, jose.ECDH_ES_A256KW, jose.A256CBC_HS512, p)
		if err != nil {
			c.String(http.StatusOK, "ooooooops")
			return
		}
		c.SetCookie("token", jwt, 3600, "/", url.Hostname(), false, true)
		c.String(http.StatusOK, "have good time with bob")
	default:
		c.String(http.StatusBadGateway, "")
	}
}

func hello(c *gin.Context) {
	session := sessions.Default(c)
	var token string
	t := session.Get("token")
	if t == nil {
		c.Redirect(http.StatusMovedPermanently, "/givemetoken")
		return
	}
	token = t.(string)
	a := session.Get("alice")
	b := session.Get("bob")
	k := session.Get("kek")
	if a == nil || b == nil {
		c.Redirect(http.StatusMovedPermanently, "/")
		return
	}
	name := c.Param("name")
	switch name {
	case "alice":
		alice := a.(*Key)
		jwt, err := c.Cookie("token")
		if err != nil || jwt == "" {
			c.String(http.StatusOK, "jwt token????")
			return
		}
		pk := ecc.NewPrivate((*alice)["x"], (*alice)["y"], (*alice)["d"])

		_, header, err := jose.Decode(jwt, pk)
		if err != nil {
			c.String(http.StatusOK, "go away")
			return
		}
		if header["alg"] == "ECDH-ES+A256KW"{
			var kek []byte
			if kek, err = getKek.Unwrap(nil, pk, 256,header); err != nil {
				c.String(http.StatusOK, "oooooooops")
				return
			}
			b, ok := k.([]byte)
			if !ok {
				c.String(http.StatusOK, "ooooooooops")
				return
			}
			if bytes.Equal(kek, b) {
				c.String(http.StatusOK, flag(token))
				return
			}
			c.String(http.StatusOK, "you are not bob!")
			return
		}
		c.String(http.StatusOK, "ECDH-ES+A256KW please")
	case "bob":
		bob := b.(*Key)
		jwt, err := c.Cookie("token")
		if err != nil || jwt == "" {
			c.String(http.StatusOK, "jwt token????")
			return
		}
		pk := ecc.NewPrivate((*bob)["x"], (*bob)["y"], (*bob)["d"])

		_, header, err := jose.Decode(jwt, pk)
		if err != nil {
			c.String(http.StatusOK, "go away")
			return
		}
		if header["alg"] == "ECDH-ES+A256KW"{
			var kek []byte
			if kek, err = getKek.Unwrap(nil, pk, 256,header); err != nil {
				c.String(http.StatusOK, "ooooooooooops")
				return
			}
			b, ok := k.([]byte)
			if !ok {
				c.String(http.StatusOK, "oooooooooooops")
				return
			}
			if bytes.Equal(kek, b) {
				c.String(http.StatusOK, flag(token))
				return
			}
			c.String(http.StatusOK, "you are not alice!")
			return
		}
		c.String(http.StatusOK, "ECDH-ES+A256KW please")
	default:
		c.String(http.StatusBadGateway, "")
	}
}

func flag(token string) string {
	h := sha256.New()
	h.Write([]byte(token+"web with crypto not always security"))
	return fmt.Sprintf("hctf{%x}",h.Sum(nil))
}

func name(curve elliptic.Curve) string {
	return fmt.Sprintf("P-%v", curve.Params().BitSize)
}

func get32D() (*big.Int, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(32), nil).Sub(max, big.NewInt(1)).Div(max, big.NewInt(179)).Div(max, big.NewInt(2447))

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return max, err
	}
	n.Mul(n, big.NewInt(179)).Mul(n, big.NewInt(2447))
	return n, nil
}

func robots(c *gin.Context) {
	c.String(http.StatusOK,"Disallow: /alice\nDisallow: /bob")
}
