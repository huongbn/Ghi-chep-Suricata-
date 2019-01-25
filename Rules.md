# Tìm hiểu về Suricata rules

# Mục lục

- [4.1 Tổng quan về rules](#41)
    - [4.1.1 Actions](#411)
    - [4.1.2 Protocol](#412)
    - [4.1.3 Source and Destinations](#413)
    - [4.1.4 Ports](#414)
    - [4.1.5 Traffic Direction](#415)
    - [4.1.6 Rules options](#416)
- [4.2 Meta-settings](#42)
    - [4.2.1 msg(message)](#421)
    - [4.2.2 sid](#422)
    - [4.2.3 Rev](#423)
    - [4.2.4 Gid](#424)
    - [4.2.5 Classtype](#425)
    - [4.2.6 Reference](#426)
    - [4.2.7 Priority](#427)
    - [4.2.8 Metadata](#428)
    - [4.2.9 Target](#429)
- [4.3 Header keyword](#43)
    - [4.3.1 IP keyword](#431)
        - [4.3.1.1 ttl](#4311)
        - [4.3.1.2 Ipopts](#4312)
        - [4.3.1.3 sameip](#4313)
        - [4.3.1.4 ip_proto](#4314)
        - [4.3.1.5 Id](#4315)
        - [4.3.1.6 Geoip](#4316)
    - [4.3.2 Fragments](#432)
        - [4.3.2.1 Fragbits](#4321)
        - [Fragoffset](#4322)
    - [4.3.3 TCP keywork](#433)
        - [4.3.3.1 seq](#4331)
        - [4.3.3.2 ack](#4332)
        - [4.3.3.3 window](#4333)
    - [4.3.4 ICMP keywork](#434)
        - [4.3.4.1 itype](#4341)
        - [4.3.4.2 icode](#4342)
        - [4.3.4.3 icmp_id](#4343)
        - [4.3.4.4 icmp_seq](#4344)
- [4.5 Payload keyword](#45)
    - [4.5.1 pcre](#451)
    - [4.5.2 Fast Pattern](#452)
        - [4.5.2.3 Fast Pattern:'chop'](#4523)
    - [4.5.3 Content](#453)
    - [4.5.4 Nocase](#454)
    - [4.5.4 Depth](#455)
    - [4.5.6 Offset](#456)
    - [4.5.7 Distance](#457)
    - [4.5.8 Within](#458)
    - [4.5.9 Isdataat](#459)
    - [4.5.10 Dsize](#4510)
    - [4.5.11 rpc](#4511)
- [4.6 HTTP Keywords](#46)
    - [4.6.1 Types of modifiers](#461)
- [4.7 Flow Keywords](#47)
    - [4.7.1 Flowbits](#471)
    - [4.7.2 Flow](#472)
    - [4.7.3 Flowint](#473)
    - [4.7.4 stream_size](#474)
- [4.10 File Keywords](#410)
- [4.9 Xbits](#49)
- [4.10 File Keywords](#410)
- [4.11 Rule Thresholding](#411)

<a name="41">

## 4.1 Tổng quan về rules
Suricata rules được chia thành 2 phần chính là: `rule header` và `rule options`.

![Imgur](https://i.imgur.com/XCGwEUo.png)

Rules header luôn là thành phần đầu tiên trong rules và nó đòi hỏi các thành phần cần có trong rules. Nó đòi hỏi các thành phần sau:

<a name="411"></a>

### 4.1.1. Actions
- Action: Việc xử lý đối vỡi dữ liệu được phân tích, các cơ chế trong mode IDS là: `Pass`, `Alert` và `Log`
    - Alert: Hệ thống tự động ghi log cảnh báo và lưu lại thông tin packet được phân tích có dâu hiệu.
    - Log: Tương tự Alert nhưng không lưu lại dữ liệu được phân tích khi có cảnh bảo
    - Pass: Thông báo không tiếp tục xử lý gói tin

<a name="412"></a>

### 4.1.2 Protocol
Xác định giao thức sử dụng và đồng thời thông báo cho hệ thống biết nhóm rules nào sẽ được sử dụng. Có thể chọn một trong 4 giao thức như: `tcp`, `udp`, `icmp` và `ip`. Ngoài ra còn có thêm một số lựa chọn khác như: `http`, `ftp`, `tls`(bao gồm cả ssl).
- Ví dụ về 1 rule `tcp`:

![Imgur](https://i.imgur.com/4OA4XCM.png)

<a name="413"></a>

### 4.1.3 Sourrce and Destinations
Xác định đích và nguồn IP của gói tin, xác định các IP hoặc dải IP sẽ được xử lý. trong quá trình cấu hình cho mã nguồn mở thì thành phần này càng được làm rõ thì hệ thống xử lý càng nhanh và đỡ tiêu tốn tài nguyên.
Có thể sử dụng biến `HOME_NET` và `EXTERNAL_NET` trong `yaml file` để cấu hình địa chỉ nguồn và địa chỉ đích. Tham khảo [Rule_vars](https://suricata.readthedocs.io/en/suricata-4.0.5/configuration/suricata-yaml.html#suricata-yaml-rule-vars)để có thể hiểu rõ hơn về vấn đề này.

Trong quá trình cấu hình địa chỉ nguồn và đích cho gói tin, có thể sử dụng tùy chọn `!`.
- Ví dụ:
```
! 1.1.1.1        # Mọi địa chỉ ngoại trừ địa chỉ 1.1.1.1
```

<a name="4.1.4"></a>

### 4.1.4 Ports
Xác định địa chỉ nguồn và đích của gói tin. HTTP port là 80, https port 443. Thông thường source port được để thiết lập là `any`. Một vài tùy chọn khi khai báo port như:
- !: Chỉ định mọi port ngoại trừ port này
- :: Định nghĩa một khoảng port chạy từ đâu tới đâu
- []: signs to make clear which parts belong together
- ,: Khai báo từng port riêng biệt

<a name="415"></a>

### 4.1.5 Traffic Direction
ác định chiều hướng đi của dữ liệu được phân tích. Có 2 dạng đó là
- Dữ liệu vào: ->
- Dữ liệu ra vào: <>
Vì có 2 lựa chọn nên trong việc tạo luật cần xác định rõ thứ tự ưu tiên phân tích gói tin cho hệ thống xử lý.

<a name="416"></a>

### 4.1.6 Rules options
Rule header chịu chức năng chính được mô tả giống như ai sẽ alf người chịu trách nhiệm, còn rule options có chức năng là vấn đề gì. Nó cho biết là sẽ tìm kiếm dấu hiệu gì trên các gói tin và làm sao để tìm kiếm nó.

Nội dung bên trong rules options là các biến số và nó có các lựa chọn khác nhau tùy vào cách tạo các rules. Các biến số này có dạng như sau: `<option>:<values>`; Options này bao gồm tên và giá trị của no, được phân cách với nhau bởi dấu hai chấm.

<a name="42"></a>

## 4.2 Meta-settings

<a name="421"></a>

### 4.2.1 msg(message)
Được sử dụng để mô tả cảnh báo cho hệ thống, nó sẽ hiển thị khi người phân tích nhận các cảnh báo
- Ví dụ:
```
ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted
OS-WINDOWS SMB NTLM NULL session attempt
EXPLOIT-KIT Blackholev2 exploit kit jar file downloaded
```

<a name="422"></a>

### 4.2.2 sid(signature id)
Được sử dụng để xác định tính duy nhất các rules được tạo. Mỗi rules có một giá trị duy nhất và không trùng nhau. Một dải sid được xác định như sau:
- 0-1000000: Sử dụng bởi sourcefire VRT
- 2000001-2999999: Sử dụng bởi Emerging Threats
- 3000000+: Sử dụng khi tạo rules mới

<a name="423"></a>

### 4.2.3 Rev(Revision)
Là tùy chọn để xác định khi một rules được thay đổi. Lúc một rules mới được tạo ra, tốt nhất nên khai báo `rev:1` để xác định nó là phiên bản đầu tiên của rules được tạo ra. Thay vì tạo sid mới khi thay đổi một rule, khi tạo luật nên giữ nguyên sid và thay đổi rev của nó.

<a name="424"></a>

### 4.2.4 Gid(group id)
Gid giống như sid. Mặc định Gid có giá trị là 1. Gid chỉ có thể nhận biết được bằng cách xem log cảnh báo
- Ví dụ dưới đây được check tại `fast.log`. Cảnh báo có `gid là 1`, `sid là 2008124` và `rev là 2`.

![Imgur](https://i.imgur.com/E9ORuhw.png)

<a name="425"></a>

### 4.2.5 Classtype
Được dùng để nhóm các loại rules vào các dạng tấn công mạng. Mỗi classtype bao gồm short name hoặc long name và chỉ số priority.
- Ví dụ:

![Imgur](https://i.imgur.com/JKQl0St.png)

<a name="426"></a>

### 4.2.6 Reference
Cung cấp thêm thông tin về luật được tạo. Thông thường nó được thêm vào là các đường dẫn ra ngoài cung cấp cụ thể về thông tin các luật được tạo:
- Ví dụ về url reference
```
reference: url, www.info.nl
```
- Một số định dạng cho reference như sau:
```
system             URL Prefix
bugtraq            http://www.securityfocus.com/bid
cve                http://cve.mitre.org/cgi-bin/cvename.cgi?name=
nessus             http://cgi.nessus.org/plugins/dump.php3?id=
arachnids          (No longer available but you might still encounter this in signatures.)
                   http://www.whitehats.com/info/IDS
mcafee             http://vil.nai.com/vil/dispVirus.asp?virus_k=
url                http://
```

<a name="427"></a>

### 4.2.7 Priority
Là thứ tự ưu tiên khi phân tích dữ liệu của các rules, nó có giá trị từ `1-255`. Gía trị từ 1-4 được sử dụng nhiều nhất. Rules nào có độ ưu tiên cao hơn sẽ được kiểm tra trước. Priority cao nhất là 1. Priority có thể kiểm tra tại `classtype`.
- Cú pháp:
```
priority:<value>;
```

<a name="43"></a>

## 4.3 Header keyword

<a name="431"></a>

### 4.3.1 IP keyword

<a name="4311"></a>

#### 4.3.1.1 ttl
ttl được dùng để kiểm tra thời gian sống time-to-live của gói tin IP.
- Cú pháp định dạng như sau:
```
ttl:<number>
```
- Lưu ý:
Nếu ttl được thiết lập là `0`, gói tin sẽ bị hủy ngya lập tức. Time-to-live dựa theo số `hop`. 

<a name="4312"></a>

#### 4.3.1.2 Ipopts
Ipopts được thiết lập tại vị trí bắt đầu của rule. Ipopts có một vài tùy chọn đặc biệt như sau:

![Imgur](https://i.imgur.com/ZEdkA2t.png)

- Cú pháp:
```
ipopts: <name>
```

<a name="4313"></a>

#### 4.3.1.3 sameip
sameip được dùng để kiểm tra địa chỉ nguồn và địa chỉ đích của gói tin xem có giống nhau hay không
- Cú pháp:
```
sameip;
```

<a name="4315"></a>

#### 4.3.1.5 Id
Mỗi packet đều có IP ID. Khi thực hiện phân mảnh gói tin, tất cả các mảnh đều có cùng ID với nhau. Điều này giúp cho bên nhận sẽ biết được các phân mảnh này thuộc cùng 1 gói tin và dễ dàng lắp ghép lại thành gói tin hoàn chỉnh.
- Cú pháp:
```
id:<number>;
```

<a name="4316"></a>

#### 4.3.1.6 Geoip
Geoip là từ khóa để thiết lập xem gói tin xuất phát từ đâu, muốn đi đến đâu, xuất phát đến vùng nào, có vị trí địa lý ở đâu
- Cú pháp:
```
geoip: src, RU;            # source address khớp với vùng miền được khai báo
geoip: both, CN, RU;       # source và dst address khớp với vùng miền được khai báo
geoip: dst, CN, RU, IR;
geoip: both, US, CA, UK;
geoip: any, CN, IR;
```

<a name="432"></a>

### 4.3.2 Fragments

<a name="4321"></a>

#### 4.3.2.1 Fragbits
Fragbits được dùng để kiểm tra về tính phân mảnh của gói tin, nó được thiết lập trong tiêu đề của gói tin và nằm tại vị trí đầu của rule. 
- Cú pháp:
```
fragbits:[*+!]<[MDR]>;
fragbits: - M: tiếp tục phân mảnh gói tin
          - D: không phân mảnh
          - R: Reversed bit
```
Một vài tuy chọn đi kèm theo như:
```
+ : Khóp với bit được chỉ định
* : Khớp với bất kì bit nào được thiết lập
! : Khớp nếu không có bit nào được thiết lập
```

<a name="433"></a>

### 4.3.3 TCP keyword

<a name="4331"></a>

#### 4.3.3.1 seq
Seq được dùng để kiểm tra TCP sequence number. Số thứ tự SN tăng lên 1 mỗi khi  byte dữ liệu được truyền đi
- Cú pháp:
```
seq:0;
```

<a name="4333"></a>

### 4.3.3.3 window
Window được dùng để kiểm tra kích thước cửa sổ trượt. Window size có giá trị từ 2 cho tới 65535.
- Cú pháp:
```
window:[!]<number>;
```

<a name="434"></a>

### 4.3.4 ICMP keyword
Tham khảo thêm về ICMP keyword [Tại đây](https://suricata.readthedocs.io/en/suricata-4.0.5/rules/header-keywords.html)

<a name="45"></a>

## 4.5 Payload keyword

<a name="451"></a>

### 4.5.1 pcre
pcre - Perl compatible Regular expressions: Trong một số trường hợp không thể sử dụng các phương pháp thông thường để nhận dạng các dấu hiệu tấn công mạng. Đối với các trường hợp này, có thể sử dụng tới `regex` để xác định các dấu hiệu tấn công mạng. Regex là một ngôn ngữ mạng trong việc xác định và nhận dạng các dạng chuối, kí tự... Hiện nay được sử dụng rộng rãi, đặc biệt là trong việc nhận dạng tấn công mạng của các sản phẩm an toàn thông tin.

Trong mỗi rules sẽ có thêm keyword `pcre` để xác định các dạng dấu hiệu. Ví dụ rule phát hiện các credit có thể được viết như sau:
```
alert ip any any -> any any (msg:“ET POLICY SSN Detected in Clear Text (dashed)”; pcre:”/ ([0-6]\d\d|7[0-2 56]\d|73[0-3]|77[0-2])-\d{2}-\d{4} /”;reference:url,doc.emergingthreats.net/2001328; classtype:policy-violation; sid:2001328; rev:13;)
```
- Cấu trúc cú pháp của pcre như sau:
```
pcre:<regular expression>;
```

<a name="452"></a>

### 4.5.2 Fast Pattern
Trong cấu trúc rule của Suricata, mỗi rule chỉ sử dụng duy nhất 1 nội dung `content` để giám sát các gói tin mạng trong môi trường Multi Pattern Matcher(MPM). Nếu trong rule có nhiều hơn một content được khai báo, Suricata sẽ sử dụng content có độ dài nhất và nọi dung chi tiết nhất.

Ví dụ sau khai báo 3 nội dung, content đầu tiên dài nhất sẽ được ưu tiên sử dụng.
```
User-agent: Mozilla/5.0 Badness;

content:”User-Agent|3A|”;
content:”Badness”; distance:0;
```

Với từ khóa `fast_pattern`, có thể chỉ định Suricata sử dụng bất kì 1 content nào trong rule. Thây vì sử dụng content `User_Agent`, ta sẽ chỉ định content `Badness` với keyword `fast_pattern` ở phía sau
```
content:”User-Agent|3A|”;
content:”Badness”; distance:0; fast_pattern;
```

<a name="4523"></a>

### 4.5.2.3 Fast_pattern:'chop'
Keyword này được sử dụng để match với 1 phần nào đó được chỉ định trong content
- Ví dụ thực hiện kiểm tra 4 kí tự cuối trong content
```
content: “aaaaaaaaabc”; fast_pattern:8,4;
```

<a name="453"></a>

### 4.5.3 Content
Là dấu hiệu để xác định các mối hiểm họa an ninh mạng có thể xyar ra. Dấu hiệu có thể được sử dụng kết hợp nhiều dấu hiệu khác.
- Cú pháp:
```
content: ”............”;
content:“USER”; content:!“anonymous”;
```

Một vài kí tự đặc biệt có thể được biểu diễn như sau:
```
“     |22|
;     |3B|
:     |3A|
|     |7C|
```

<a name="454"></a>

### 4.5.4 Nocase
Sử dụng trong content để giúp các luật không phân biệt chữ hoa và chữ thường.
- Cú pháp:
```
nocase;
```
- Ví dụ:
```
content:"root";nocase;
```
Ví dụ trên giúp hệ thống phát hiện tất cả các từ khóa `root` mà không phân biệt chữ hoa và chữ thường

<a name="455"></a>

### 4.5.5 Depth và Offset
Xác định vị trí bắt đầu phân tích trong một payload, thông thường nếu không khai báo gì thì hệ thống sẽ phân tích gói tin từ đầu tới hết, còn nếu là `1` thì hệ thống chỉ bắt đầu phân tích gói tin từ byte thứ 2 đến hết. Ngoài ra, nó còn cho phép xác định vị trí các dấu hiệu cần được kiểm tra để cảnh báo và giảm thiểu các cảnh báo sai.

![Imgur](https://i.imgur.com/jqTwxpP.png)

- Ta cùng so sánh 2 ví dụ sau đây:
```
alert tcp $HOME_NET any ->67.205.2.30 21 (msg:“Suspicious FTP Login”;
content:“guest”; sid:5000000; rev:1;)
```
```
alert tcp $HOME_NET any -> 67.205.2.30 21 (msg:“Suspicious FTP Login”
content:“guest”; offset:5; sid:5000000; rev:1;)
```
Hai ví dụ trên xác định luật cho hệ thống khi có người dùng đăng nhập vào tài khoản guest, nhưng trong trường hợp này nếu không có offset thì hệ thống cảnh báo dễ bị nhầm lẫn khi có người dùng khác cùng đăng nhập vào tài khoản khác nhưng truy cập vào thư mực guest. Để giảm thiểu các cảnh báo sai, khi tạo luật cần chỉ rõ vị trí của giá trị cần kiểm tra. 

![Imgur](https://i.imgur.com/2iQu5H3.png)

Depth và offset có thể suer dụng đồng thời với nhau

<a name="457"></a>

### 4.5.7 Distance và within
Sử dụng khi có nhiều giá trị kiểm tra trong thành phần content của rules. Mục đích là xác định khoảng cách để tiếp tục kiểm tra các giá trị tiếp theo trên payload của dữ liệu
- ví dụ sau đây cho thấy, sau khi kiểm tra nội dung giá trị payload thứ nhất thì sau 16 byte mới tiếp tục kiểm tra nội dụng content thứ 2
```
alert tcp $HOME_NET 1024: -> $EXTERNAL_NET 1024: (msg:“ET P2P Ares Server Connection”; flow:established,to_server; dsize:<70; content:“r|be|bloop|00|dV”; content:“Ares|00 0a|”;
distance:16;reference:url,aresgalaxy.sourceforge.net;reference:url,doc.emergingthreats.net/bin/view/Main/2008591; classtype:policy-violation;
sid:2008591; rev:3;)
```

![Imgur](https://i.imgur.com/lyTPN6v.png)

Distance có thể sử dụng số âm. Ví dụ sau:

![Imgur](https://i.imgur.com/pTzSCw2.png)

<a name="459"></a>

### 4.5.9 Isdataat
Isdatat là từ khóa để kiểm tra 1 vị trí bất kì trong payload. Ngoài ra còn có 1 keyword khác nữa là `relative`, được sử dụng để kiểm tra payload tại 1 vị trí bất kì kể từ content trước.
- Ví dụ sau thực hiện kiểm tra byte thứ 512 của payload. Dòng thứ 2 kiểm tra byte thứ 50 của payload kể từ content thứ nhất.
```
isdataat:512;

isdataat:50, relative;
```
![Imgur](https://i.imgur.com/yjU2s6Z.png)

<a name="4510"></a>

### 4.5.10 Dsize
Từ khóa này dùng kể kiểm tra kích thước của payload, nó còn thuận tiện trong việc xem hệ thống có bị tràn bộ đệm hay không
- Cú pháp:
```
dsize:<number>;
```

<a name="4512"></a>

### 4.5.12 Replace
Replace là keyword chỉ có thể sử dụng trong chế độ `IPS`. Ví dụ sau sẽ thay đổi content `abc` thành `def` phục vụ cho mục đích ngăn chặn xâm hại

![Imgur](https://i.imgur.com/ug5jIAF.png)

<a name="46"></a>

## 4.6 HTTP Keywords

### 4.6.1 Types of modifiers

<a name="47"></a>

## 4.7 Flow Keywords

### 4.7.1 Flowbits

Flowbits gồm 2 phần. Phần đầu tiên mô tả hành động mà nó sẽ thực hiện, phần thứ 2 chỉ ra tên của Flowbits

Có nhiều packet thuộc về 1 flow. Suricata lưu giữ các flow này trong memory. Để biết thêm thông tin chi tiết, truy cập [Flow Settings](https://suricata.readthedocs.io/en/suricata-4.0.5/configuration/suricata-yaml.html#suricata-yaml-flow-settings). Flowbits sẽ tạo ra một cảnh báo khi mà hai gói tin khác nhau lại có sự giống nhau về dữ liệu bên trong. 

Flowbits có các hành động như sau: 

```
flowbits: set, name      # thiết lập điều kiện `name` trong flow nếu có
flowbits: isset, name    # được sử dụng để tạo ra cảnh báo nếu rule phát hiện trùng khớp với điều kiện đã được thiết lập
flowbits: toggle, name   # đảo ngược lại cài đặt hiện tại đã theiets lập cho flow
flowbits: unset, name    # bỏ điều kiện trong flow
flowbits: isnotset, name # tạo ra cảnh báo khi rule khớp và điều kiện không được thiết lập trong flow
flowbits: noalert        # không có cảnh báo
```

- Ví dụ:

![Imgur](https://i.imgur.com/jba1rON.png)


### 4.7.2 Flow

Chỉ ra nơi mà gói tin xuất phát hoặc đích mà gói tin cần đến. Một vài hành động của flow như:

- **to_client**: Các gói tin từ server tới client
- **to_server**: Các gói tin từ client tới server
- **from_client**: Giống như to_server
- **from_server**: Giống như to_client
- **established**: Đang thiết lập kết nối
- **not_established**: Ngược lại với established
- **stateless**: Match on packets that are and are not part of an established connection.
- **only_stream**: Match on packets that have been reassembled by the stream engine
- **no_stream**: Match on packets that have not been reassembled by the stream engine. Will not match packets that have been reeassembled.
- **only_frag**: Kết hợp gói tin từ các mảnh
- **no_frag**: Kết hợp gói tin chưa được tập hợp từ các mảnh

Ví dụ về TCP connection thiết lập kết nối bắt tay 3 bước

![Imgur](https://i.imgur.com/NTJbDVi.png)


Đối với các giao thức khác, ví dụ như UDP, kết nối được coi là được thiết lập sau khi nhìn thấy lưu lượng truy cập từ cả hai phía

![Imgur](https://i.imgur.com/WwC2WWV.png)

<a name="49"></a>

## 4.9 Xbits

Đặt, bỏ đặt, chuyển đổi và kiểm tra các bit được lưu trữ trên mỗi host hoặc ip_pair

- Cú pháp:

```
xbits:noalert;
xbits:<set|unset|isset|toggle>,<name>,track <ip_src|ip_dst|ip_pair>;
xbits:<set|unset|isset|toggle>,<name>,track <ip_src|ip_dst|ip_pair> \
    [,expire <seconds>];
xbits:<set|unset|isset|toggle>,<name>,track <ip_src|ip_dst|ip_pair> \
    [,expire <seconds>];
```
<a name="410"></a>

## 4.10 File Keywords

### 4.10.1 filename

- Chỉ ra tên file
- Cú pháp:

```
filename:<string>;
filename:"secret";
```

### 4.10.2 fileext

- Chỉ ra định dạng của file
- Cú pháp:

```
fileext:<string>;
fileext:"jpg";
```

### 4.10.3 filemagic

- Matches on the information libmagic returns about a file.
- Cú pháp:

```
filemagic:<string>;
filemagic:"executable for MS Windows";
```

### 4.10.4 filestore

- Chỉ ra vị trí lưu giữ file
- Cú pháp:

```
filestore:<direction>,<scope>;
```

direction là 1 trong các trường hợp sau:
- request/to_server: store a file in the request / to_server direction
- response/to_client: store a file in the response / to_client direction
- both: store both directions

scope can be:
- file: only store the matching file (for filename,fileext,filemagic matches)
- tx: store all files from the matching HTTP transaction
- ssn/flow: store all files from the TCP session/flow.

### 4.10.5 filemd5

- Match file MD5 against list of MD5 checksums.
- Cú pháp:
```
filemd5:[!]filename;
```

### 4.10.6 filesize

- Match on the size of the file as it is being transferred.
- Cú pháp:
```
filesize:<value>;
```

```
filesize:100; # exactly 100 bytes
filesize:100<>200; # greater than 100 and smaller than 200
filesize:>100; # greater than 100
filesize:<100; # smaller than 100
```
<a name="411"></a>

## 4.11 Rule Thresholding

- Thresholding can be configured per rule and also globally

### threshold

- Được sử dụng để kiểm soát tần suất xuất hiện cảnh báo. Nó có 3 mode là: threshold, limit hoặc both
- Cú pháp:
```
threshold: type <threshold|limit|both>, track <by_src|by_dst>, count <N>, seconds <T>
```

#### 4.11.1.1 type "threshold"

Loại này được sử dụng để đặt ngưỡng tối thiểu cho quy tắc trước khi nó tạo ra 1 cảnh báo.
- Ví dụ:
```
alert tcp !$HOME_NET any -> $HOME_NET 25 (msg:"ET POLICY Inbound Frequent Emails - Possible Spambot Inbound"; \
flow:established; content:"mail from|3a|"; nocase;                                                       \
threshold: type threshold, track by_src, count 10, seconds 60;                                           \
reference:url,doc.emergingthreats.net/2002087; classtype:misc-activity; sid:2002087; rev:10;)
```

Rule này sẽ thiết lập cảnh báo khi máy chủ nhận được 10 emails từ cùng 1 máy trạm trong khoảng thời gian 1 phút

#### 4.11.1.2 type "limit"

Giới hạn số lần cảnh báo khi rule match
- Ví dụ:

```
alert http $HOME_NET any -> any $HTTP_PORTS (msg:"ET USER_AGENTS Internet Explorer 6 in use - Significant Security Risk"; \
flow:to_server,established; content:"|0d 0a|User-Agent|3a| Mozilla/4.0 (compatible|3b| MSIE 6.0|3b|";                \
threshold: type limit, track by_src, seconds 180, count 1;                                                           \
reference:url,doc.emergingthreats.net/2010706; classtype:policy-violation; sid:2010706; rev:7;)
```

Ví dụ trên nói rằng sẽ có 1 cảnh báo được tạo ra trong vòng 3 phút nếu nội dung MSIE 6.0 được phát hiện

#### 4.11.1.3 type "both"

Loại này kết hợp 2 loại trên
- Ví dụ:

```
alert tcp $HOME_NET 5060 -> $EXTERNAL_NET any (msg:"ET VOIP Multiple Unauthorized SIP Responses TCP"; \
flow:established,from_server; content:"SIP/2.0 401 Unauthorized"; depth:24;                      \
threshold: type both, track by_src, count 5, seconds 360;                                        \
reference:url,doc.emergingthreats.net/2003194; classtype:attempted-dos; sid:2003194; rev:6;)
```

Rule này chỉ ra rằng cảnh báo chỉ được tạo ra nếu trong vòng 6 phút có từ 5 responses SIP TCP 401 trái phép trở lên và nó chỉ cảnh báo 1 lần trong vòng 6 phút này

### 4.11.2 detection_filter

Từ khóa detect_filter được sử dụng để cảnh báo trên mỗi rule sau khi nó đạt đến giá trị ngưỡng. Nó khác với threshold và type threshold ở chỗ nó tạo ra cảnh báo cho mỗi rule khi nó đạt ngưỡng đã được set, trong khi đó lần thứ 2 sẽ đặt lại giá trị bộ đếm và cảnh báo lại khi ngưỡng lại đạt đến giá trị đã được set

- Ví dụ:

```
alert http $EXTERNAL_NET any -> $HOME_NET any \
     (msg:"ET WEB_SERVER WebResource.axd access without t (time) parameter - possible ASP padding-oracle exploit"; \
     flow:established,to_server; content:"GET"; http_method; content:"WebResource.axd"; http_uri; nocase;          \
     content:!"&t="; http_uri; nocase; content:!"&amp|3b|t="; http_uri; nocase;                                    \
     detection_filter:track by_src,count 15,seconds 2;                                                             \
     reference:url,netifera.com/research/; reference:url,www.microsoft.com/technet/security/advisory/2416728.mspx; \
     classtype:web-application-attack; sid:2011807; rev:5;)
```

Rule trên chỉ ra rằng sau 15 lần match trong 2s thì sẽ tạo ra cảnh báo



