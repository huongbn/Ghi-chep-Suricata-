# Đôi chút về sự khác nhau giữa Snort và Suricata

Network Intrusion Detection Systems ra đời vào những năm 1980, IDS Snort được tạo ra bởi Martin Roesch. Ưu điểm của nó là tính thiết kế nhỏ gọn `light-weight` và triển khai linh hoạt. Trong thời gian gần đây, xuất hiện thêm opensource IDS là Suricata. Sau đây sẽ là một vài điểm khác biệt giữa hai opensource này như sau: 

# 1. Rules
Snort được hỗ trợ từ cộng đồng rất nhiều, điều này dẫn tới các rules được gia tăng đáng kể và cập nhật một cách thường xuyên. Cú pháp các quy tắc đơn giản, dễ dàng triển khai. Một số tổ chức thương mại phát triển thêm về các rules tròn Snort mà người dùng sẽ phải trả phí nếu như muốn dùng chúng. Kể đến như [Talos'SO/VRT](https://www.snort.org/talos) rules được phát hành 1 tháng 1 lần hoặc như [CrowdStrikes Threat Intelligence Services](https://www.crowdstrike.com/products/falcon-x/)

Suricata có quy tắc các rules tương đồng như với Snort. VRT rules vẫn làm việc bình thường nhưng không phải là tất cả đều hoạt động. Suricata có quy tắc riêng, [Emerging Threats](https://www.proofpoint.com/us) bản free sẽ được phát hành sau `30-60` ngày kể từ ngày phát hành cho các tổ chức sử dụng có trả phí

# 2. Application Detection


# 3. Multithreating
Một trong những ưu điểm lớn nhất của Suricata so với Snort là nó ra đợi trong những năm gần đây, nó có những tính năng mà Snort không có, điển hình là Suricata hỗ trợ `đa luồng-multithreating`. Đây được coi là ưu điểm lớn nhất của Suricata so với Snort.

Đối với Snort, chỉ 1 luồng duy nhất được sử dụng cho dù CPU có bao nhiều core, mỗi core có nhiều luồng đi chăng nữa.

# 4. File Extaction
Suricata hỗ trợ việc trích xuất tập tin. Đây là một tính năng cực kì hữu ích, cho phép trích xuất tự động các file đã chọn sau khi rule có chứa keyword `filestore`.



# Tham khảo
- https://resources.infosecinstitute.com/open-source-ids-snort-suricata/#gref
- https://www.aldeid.com/wiki/Suricata-vs-snort