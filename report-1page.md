# Report 1 page - Lab 5 AES-128

## Mục tiêu

Bài thực hành nhằm mô tả và triển khai toàn bộ chuỗi xử lý AES-128 ở mức nhập môn: mở rộng khóa, SubBytes, ShiftRows, MixColumns, AddRoundKey và padding block 128-bit. Mục tiêu là xây dựng chương trình `encrypt`/`decrypt` hoạt động với dữ liệu văn bản đầu vào, lưu ciphertext nhị phân và khôi phục đúng plaintext ban đầu.

## Cách làm / Method

- `encrypt.cpp` đọc plaintext từ stdin, chuyển thành chuỗi byte và áp dụng PKCS#7 padding để đảm bảo độ dài là bội số 16.
- `structures.h` lưu S-box, inverse S-box, các bảng nhân trong GF(2^8), RCon và hàm `KeyExpansion` để sinh 11 round key cho AES-128.
- `encrypt.cpp` mã hóa từng block 16 byte với hàm `AESEncrypt`, sau đó ghi ciphertext nhị phân vào file `message.aes` và in hex ra màn hình.
- `decrypt.cpp` đọc file `message.aes` dưới chế độ binary, giải mã từng block, kiểm tra và loại bỏ PKCS#7 padding, rồi in plaintext ra màn hình.
- `keyfile` chứa 16 byte khóa AES-128 dưới dạng hex text, được phân tích và kiểm tra định dạng trước khi mở rộng khóa.

## Kết quả / Result

- `encrypt` tạo ra file `message.aes` nhị phân và in ciphertext hex.
- `decrypt` đọc toàn bộ file nhị phân, giải mã đúng từng block và phục hồi plaintext ban đầu mà không bị lệ thuộc vào byte `0x00` trong ciphertext.
- Đã xử lý an toàn I/O nhị phân cho `message.aes`, tránh dùng `getline()` và `strlen()` cho dữ liệu ciphertext.
- Đã bổ sung PKCS#7 padding, giúp loại trừ nhầm lẫn giữa dữ liệu thực và byte padding.
- File `README.md` đã cập nhật hướng dẫn chạy, cách tạo khóa và padding dùng trong bài.

## Kết luận / Conclusion

Bài lab thể hiện rõ các bước cốt lõi của AES-128 và nhấn mạnh hai điểm quan trọng:

- xử lý dữ liệu nhị phân cần dùng `read`/`write` thay vì chuỗi C-style;
- padding phải được chọn phù hợp với block cipher để tránh sai lệch dữ liệu.

Trong phiên bản hiện tại, hệ thống đã sử dụng PKCS#7 padding và lưu ciphertext dưới dạng binary. Nâng cấp tiếp theo có thể là thêm xác thực dữ liệu (MAC/HMAC) hoặc kiểm thử với known-answer test vector chuẩn AES.
