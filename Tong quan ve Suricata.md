# Tìm hiểu về Suricata

## Mục lục
- [1. Cài đặt Suricata](#1)

Suricata là giải pháp IDS/IPS mã nguồn mở hiệu quả cho các hệ thống mạng chưa được đầu tư các giải pháp IDS/IPS thương mại. Nó được xây dựng từ các thành phần khác nhau và khả năng hoạt động của nó tùy thuộc vào cách thức cấu hình, cài đặt cho hệ thống. Ở chế độ mặc định được xem là cơ chế hoạt động tương đối tối ưu cho việc phát hiện các dạng tấn công mạng.

Bước đầu tiên trong quá trình xử lý là thu thập các gói tin với module Packet Acquisition. Mudule này có chức năng thu thập gói tin từ cổng mạng và chuyển tiếp chúng đến để giải mã gói tin(decoder), nơi chịu trách nghiệm cho việc xác đinh các loại liên kết và chuẩn hóa dữ liệu cho các tiến trình khác. Tiếp theo, dữ liệu sẽ được chuyển tới stream module. Stream làm nhiệm vụ nhóm các dạng dữ liệu và reassembly các gói dữ liệu. Kế tiếp dữ liệu được đưa vào module phát hiện, nơi phân tích gói tin để phát hiện các tân công mạng dựa trên các dấu hiệu. Cuối cùng, cảnh báo được đưa ra khi có các dấu hiệu được phát hiện và được gửi tới output module, dữ liệu đầu ra có thể được xác định ở nhiều dạng khác nhau.

Suricata có thể được triển khai theo 02 cơ chế: cơ chế phát hiện(IDS) và ngăn chặn(IPS).
Khi triển khai theo cơ chế IPS, toàn bộ dữ liệu phân vùng mạng được cấu hình đi qua thiết bị thu thập log với 02 cổng mạng và sử dụng Iptables để chuyển tiếp dữ liệu an toàn. Quá trình được mô tả như hình dưới. 

![Imgur](https://i.imgur.com/WAOWYYu.png)

![Imgur](https://i.imgur.com/3YxZDA0.png)

Theo đó, dữ liệu vào hệ thống mạng được đi qua cổng mạng thứ 1, tại đây hệ thống tiến hành phân tích gói tin và đưa ra các xử lý. Các dạng xử lý bao gồm: Pass, Drop, Reject, Alert đối với chế độ IPS, và Pass, Alert, Log đối với chế độ IDS.

Như vậy, đối với các dữ liệu bình thường sẽ được chuyển sang cổng mạng thứ 2 bằng cách sử dụng forward trong Iptables.
```
sudo iptables -I FORWARD -i eth0 -o eth1 -j NFQUEUE
sudo iptables -I FORWARD -i eth1 -o eth0 -j NFQUEUE
```

Đối với tích hợp chế độ IDS lên hệ thống thu thập dữ liệu thông qua tính năng SPAN PORT trên switch. Từ đó, dữ liệu theo các tiến trình xử lý và đưa ra các cảnh báo về an ninh mạng.

Ngoài khoảng số lượng lớn luật được tích hợp sẵn, suricata cho phép định dạng các luật mới cho hệ thống dựa trên các dấu hiệu nhận dạng và các hành vi. Các thành phần trong việc tạo luật trên mã nguồn mở tương đối dể hiểu.
- Ví dụ sau đây hệ thống sẽ đưa ra cảnh báo khi có người dùng tải file có nội dung chứa từ khóa `evil`.

```
alert tcp $EXTERNAL_NET 80 ->$HOME_NET any (msg:”Users Downloading
Evil); content:”evil”; sid:55555555; rev:1;
```

<a name="1"></a>

# 1. Cài đặt Suricata

## 1.1 Cài đặt từ Source
Tiến hành tải gói cài đặt Suricata [Tại đây](https://suricata-ids.org/download/)

```
tar xzvf suricata-4.0.0.tar.gz
cd suricata-4.0.0
./configure
make
make install
```

Sau khi cài đặt thành công, file cấu hình mặc định nằm tại `/usr/local/etc/suricata`, và file log nằm tại `/usr/local/var/log/suricata`

### 1.1.1 Một vài tùy chọn cấu hình như sau
- **--disable-gccmarch-native**: Do not optimize the binary for the hardware it is built on. Add this flag if the binary is meant to be portable or if Suricata is to be used in a VM.
- **--prefix=/usr/**: Cài đặt Suri nằm tại `/usr/bin`. Default tại `/usr/local/`
- **--localstatedir=/var**: Định nghĩa lại file log nằm tại `/var/log/suricata` thay vì mặc định `/usr/local/var/log/suricata`
- **--enable-lua**: Enable Lua
- **--enable-geoip**: Enable GeoIP hỗ trợ cho việc detection 
- **--enable-rust**: Enables experimental Rust support

### 1.1.1.1 Ubuntu/Debian
- Minimal:
```
apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                make libmagic-dev
```
- Recommended:
```
apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
                libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev        \
                libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev
```
- Extra for iptables/nftables IPS integration:
```
apt-get install libnetfilter-queue-dev libnetfilter-queue1  \
                libnetfilter-log-dev libnetfilter-log1      \
                libnfnetlink-dev libnfnetlink0
```
- For Rust support (Ubuntu only):
```
apt-get install rustc cargo
```

## 1.2 Binary packages
### 1.2.1 Ubuntu
```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```

### 1.2.2 Debian
```
apt-get install suricata
```

### 1.2.3 Fedora
```
dnf install suricata
```

### 1.2.3 RHEL/CentOS
```
yum install epel-release
yum install suricata
```