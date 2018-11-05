# Tìm hiểu về Suricata rules

# Mục lục
- [4.13 SSL/TLS Keywords](#413)
    - [4.13.1 tls_cert_subject](#4131)
    - [4.13.2 tls_cert_issuer](#4132)
    - [4.13.3 tls_cert_serial](#4133)
    - [4.13.4 tls_sni](#4134)
    - [4.13.5 tls_cert_notbefore](#4135)
    - [4.13.6 tls_cert_notafter](#4136)
    - [4.13.7 tls_cert_expired](#4137)
    - [4.13.8 tls_cerT_valid](#4138)
    - [4.13.9 tls.version](#4139)
    - [4.13.10 tls.subject](#41310)
    - [4.14.11 tls.issuerdn](#41311)
    - [4.13.12 tls.fingerprint](#41312)
    - [4.13.13 tls.store](#41313)
    - [4.13.14 ssl_state](#41314)
- [4.14 Modbus Keyword](414)
- [4.15 DNP3 Keywords](#415)
- [4.16 ENIP/CIP Keywords](#416)
- [4.17 Generic App Layer Keywords](#417)
- [4.18 Lua Scripting](#418)
- [4.19 Normalized Buffers](#419)
- [4.20 Different From Snort](#420)

<a name="413"></a>

## 4.13 SSL_TLS Keywords

<a name="4131"></a>

### 4.13.1 tls_cert_subject
Match TLS/SSL certificate Subject field.
Ví dụ:

```
tls_cert_subject; content:"CN=*.googleusercontent.com"; isdataat:!1,relative;
tls_cert_subject; content:"google.com"; nocase; pcre:"/google.com$/";
```

<a name="4.13.2"></a>

### 4.13.2 tls_cert_issuer

Match TLS/SSL certificate Issuer field.

Ví dụ:

```
tls_cert_issuer; content:"WoSign"; nocase; isdataat:!1,relative;
tls_cert_issuer; content:"StartCom"; nocase; pcre:"/StartCom$/";
```

<a name="4133"></a>

### 4.13.3 tls_cert_serial

Match on the serial number in a certificate.

Ví dụ:

```
alert tls any any -> any any (msg:"match cert serial"; \
  tls_cert_serial; content:"5C:19:B7:B1:32:3B:1C:A1"; sid:200012;)
```

<a name="4134"></a>

### 4.13.4 tls_sni
Match TLS/SSL Server Name Indication field.

Ví dụ:

```
tls_sni; content:"oisf.net"; nocase; isdataat:!1,relative;
tls_sni; content:"oisf.net"; nocase; pcre:"/oisf.net$/";
```

<a name="4135"></a>

### 4.13.5 tls_cert_notbefore
Match on the NotBefore field in a certificate.

Ví dụ:
```
alert tls any any -> any any (msg:"match cert NotBefore"; \
  tls_cert_notbefore:1998-05-01<>2008-05-01; sid:200005;)
```

<a name="4.13.6"></a>

### 4.13.6 tls_cert_notafter

Match on the NotAfter field in a certificate.

Ví dụ:

```
alert tls any any -> any any (msg:"match cert NotAfter"; \
  tls_cert_notafter:>2015; sid:200006;)
```

<a name="4137"></a>

### 4.13.7 tls_cert_expired

Match returns true if certificate is expired. It evaluates the validity date from the certificate.

Cú pháp:

```
tls_cert_expired
```

<a name="4.13.8"></a>

### 4.13.8 tls_cert_valid
Match returns true if certificate is not expired. It only evaluates the validity date. It does not do cert chain validation. It is the opposite of tls_cert_expired.

Cú pháp

```
tls_cert_valid
```

<a name="41310"></a>

### 4.13.10 tls.subject
- Ý nghĩa tuonwg đồng với `tls_cert_subject`
- Không sử dụng được `nocase`

<a name="41312"></a>

### 4.13.12 tls.fingerprint
match TLS/SSL certificate SHA1 fingerprint

Ví dụ:

```
tls.fingerprint:!"f3:40:21:48:70:2c:31:bc:b5:aa:22:ad:63:d6:bc:2e:b3:46:e2:5a"
```

Không sử dụng được `nocase`

<a name="41314"></a>

### 4.13.14 ssl_state
Chỉ ra trạng thái của kết nối SSL
- client_hello
- server_hello
- client_keyx
- unknown


<a name="417"></a>

## 4.17 Generric App Layer Keywords

<a name="4171"></a>

### 4.17.1 app-layer-protocol

Match on the detected app-layer protocol.

Cú pháp:

```
app-layer-protocol:[!]<protocol>;
```

Ví dụ:

```
app-layer-protocol:ssh;
app-layer-protocol:!tls;
app-layer-protocol:failed;  # Được sử dụng khi protocol trong flow not detected 
```

