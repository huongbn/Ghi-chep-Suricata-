# Tìm hiểu về Suricata

# Mục lục

- [4.6 HTTP Keywords](#46)
    - [4.6.1 Types of modifiers](#461)
- [4.7 Flow Keywords](#47)
    - [4.7.1 Flowbits](#471)
    - [4.7.2 Flow](#472)
    - [4.7.3 Flowint](#473)
    - [4.7.4 stream_size](#474)
- [4.9 Xbits](#49)


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

