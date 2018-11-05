# Tìm hiểu về Suricata

# Mục lục

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



