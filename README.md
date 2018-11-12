# HCTF 2018 - Web&Crypto - bestrong | simple version wp


## JWE中ECDH的加密/解密过程
根据RFC7518和jose2go的源代码，我们可以整理出以下的过程。
**加密**：从cookie获取JWT，解析JWT头，判断alg、enc->进入ECDH_ES+A256KW加密逻辑
在`jose.go`的encrypt函数中通过WrapNewKey生成加密用的密钥
![mark](http://img.tan90.me/md/181112/b33bglbDB7.png)
`ecdh_aeskw.go`中的WrapNewKey
![mark](http://img.tan90.me/md/181112/3Cc28blmFK.png)
可以看到生成的函数来自`ecdh.go`中的WrapNewKey
![mark](http://img.tan90.me/md/181112/BC5LBkffl6.png)
发现代码中只依靠pubKey.Curve去生成一个新的d,x,y，然后将数据传入deriveKey函数
![mark](http://img.tan90.me/md/181112/8d0CIAiA35.png)
最后通过KDF函数计算出kek，将kek作为参数传入aesKW.WrapNewKey
![mark](http://img.tan90.me/md/181112/ii69AiAGJH.png)
这里的WrapNewKey最核心的部分是`aes/key_wrap.go`中的代码，不再深究
![mark](http://img.tan90.me/md/181112/kj6cmjl98F.png)
这样客户端的密钥交换就完成了，剩下的只是aes加密和签名。
**解密**：同样从cookie获取JWT解析后转入ECDH_ES+A256KW解密逻辑
解密逻辑很简单，也是直接和题目关联的
![mark](http://img.tan90.me/md/181112/FiiL3c931G.png)
跟入`ecdh_aeskw.go`发现和加密一样，直接看`ecdh.go`的Unwrap函数
![mark](http://img.tan90.me/md/181112/H18jcHKCc6.png)
问题的关键就在IsOnCurve函数，题目所用的版本并没有做这一步检查
剩下传入deriveKey函数后就和加密没有什么区别了

## 攻击原理
![](https://file.tan90.me/20181111161628.png)

原先没有验证接收的点是否在P256曲线上，所以就算你给服务端的点不是基于服务端公钥的点生成的，服务端也会进行进入解密流程。因此可以构造一个不属于P256曲线上的点来生成jwe来攻击(无效曲线攻击)。

正常ecdh-es流程

![](https://file.tan90.me/20181111190153.png)

然而在ecdh-es中，椭圆曲线中的b不影响密钥交换的最终结果

![](https://file.tan90.me/20181111183637.png)

所以可以通过修改b的值来寻找一个低阶的点进行爆破

![](https://file.tan90.me/20181111184223.png)

服务端的私钥d是32位，所以选取5个阶为1000左右的点，然后使用中国剩余定理将私钥还原出来

## poc

使用sage计算低阶的点
```python
import base64
import binascii
import struct

def long_to_bytes(n, blocksize=0):
    s = b''
    n = int(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b'\x00'[0]:
            break
    else:
        # only happens when n == 0
        s = b'\x00'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b'\x00' + s
    return s

p256 = 115792089210356248762697446949407573530086143415290314195533631308867097853951
a256 = p256 - 3
FF = GF(p256)

res = []

while len(res) < 10:
        b256 = randint(2, 2^16)
        E = EllipticCurve([FF(a256), FF(b256)])
        ss = str(E.order().factor()).split('*')
        for i in ss:
                if '^' not in i:
                        i = int(i.strip())
                        if 100 < i < 2000:
                                P = E.random_point() * Integer(E.order()/i)
                                # order = P.order()
                                print i, P
                                # print str(P).split(':')
                                bp = [base64.urlsafe_b64encode(long_to_bytes(int(P[0]))), base64.urlsafe_b64encode(long_to_bytes(int(P[1])))]
                                res.append((i, bp))
                                break

print res
```
![](https://file.tan90.me/20181111194242.png)

这些是跑出来的点

![](https://file.tan90.me/20181111210042.png)

传入WrapNewKey准备生成密钥

![](https://file.tan90.me/20181111210206.png)

![](https://file.tan90.me/20181111210410.png)

5个点都跑出来后使用crt还原私钥，再用alice的公钥和还原出来的私钥生成jwt去请求bob，拿到flag

![](https://file.tan90.me/20181111210508.png)

![](https://file.tan90.me/20181111211202.png)

![](https://file.tan90.me/20181111211224.png)

### 详细原理: 

http://img.tan90.me/Invalid%20curve%20attack%20in%20JWE%20ECDH-ES.pdf (出题主要参考资料)

https://tools.ietf.org/html/rfc7518#page-66 (ecdh-es rfc例子)

https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/

http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.107.3920&rep=rep1&type=pdf

https://github.com/dvsekhvalnov/jose2go/commit/0c50fb3ad489ea07b7a1e9f34c29c0b2ce5f3fa5