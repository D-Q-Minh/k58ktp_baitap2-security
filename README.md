# k58ktp_baitap2-security
#### Bài tập 2
#### Môn: An toàn và bảo mật thông tin

######
I. MÔ TẢ CHUNG
Sinh viên thực hiện báo cáo và thực hành: phân tích và hiện thực việc nhúng, xác
thực chữ ký số trong file PDF.
Phải nêu rõ chuẩn tham chiếu (PDF 1.7 / PDF 2.0, PAdES/ETSI) và sử dụng công cụ
thực thi (ví dụ iText7, OpenSSL, PyPDF, pdf-lib).
---
II. CÁC YÊU CẦU CỤ THỂ
1) Cấu trúc PDF liên quan chữ ký (Nghiên cứu)
- Mô tả ngắn gọn: Catalog, Pages tree, Page object, Resources, Content streams,
XObject, AcroForm, Signature field (widget), Signature dictionary (/Sig),
/ByteRange, /Contents, incremental updates, và DSS (theo PAdES).
- Liệt kê object refs quan trọng và giải thích vai trò của từng object trong
lưu/truy xuất chữ ký.
- Đầu ra: 1 trang tóm tắt + sơ đồ object (ví dụ: Catalog → Pages → Page → /Contents
; Catalog → /AcroForm → SigField → SigDict).
2) Thời gian ký được lưu ở đâu?
- Nêu tất cả vị trí có thể lưu thông tin thời gian:
+ /M trong Signature dictionary (dạng text, không có giá trị pháp lý).
+ Timestamp token (RFC 3161) trong PKCS#7 (attribute timeStampToken).
+ Document timestamp object (PAdES).
+ DSS (Document Security Store) nếu có lưu timestamp và dữ liệu xác minh.
- Giải thích khác biệt giữa thông tin thời gian /M và timestamp RFC3161.
3) Các bước tạo và lưu chữ ký trong PDF (đã có private RSA)
- Viết script/code thực hiện tuần tự:
1. Chuẩn bị file PDF gốc.
2. Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes).
3. Xác định /ByteRange (loại trừ vùng /Contents khỏi hash).
4. Tính hash (SHA-256/512) trên vùng ByteRange.
5. Tạo PKCS#7/CMS detached hoặc CAdES:
- Include messageDigest, signingTime, contentType.
- Include certificate chain.
- (Tùy chọn) thêm RFC3161 timestamp token.
6. Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset.
7. Ghi incremental update.
8. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI.
- Phải nêu rõ: hash alg, RSA padding, key size, vị trí lưu trong PKCS#7.
- Đầu ra: mã nguồn, file PDF gốc, file PDF đã ký.
- 
4) Các bước xác thực chữ ký trên PDF đã ký
- Các bước kiểm tra:
1. Đọc Signature dictionary: /Contents, /ByteRange.
2. Tách PKCS#7, kiểm tra định dạng.
3. Tính hash và so sánh messageDigest.
4. Verify signature bằng public key trong cert.
5. Kiểm tra chain → root trusted CA.
6. Kiểm tra OCSP/CRL.
7. Kiểm tra timestamp token.
8. Kiểm tra incremental update (phát hiện sửa đổi).
- Nộp kèm script verify + log kiểm thử.


#### Bài làm:
##### 1. Cấu trúc PDF liên quan chữ ký:
######
  - Catalog (/Root) — entry tới /AcroForm nếu PDF có form. (gốc của cấu trúc form). 
  - Pages tree (/Pages) → Page object (/Page) — chứa /Contents (content streams), /Resources, /Annots (signature widget là một annotation trong /Annots). 
  - Resources — fonts, XObjects (gắn appearance của chữ ký).
  - Content streams — nội dung hiển thị trang (không chứa thông tin chữ ký số trực tiếp trừ khi appearance được nhúng).
  - XObject — dùng để hiển thị "appearance" (hình dấu) chữ ký nếu visible signature.
  - AcroForm (/AcroForm) — chứa form fields (bao gồm signature fields). Field refs -> widget annotations. 
  - Signature field (widget) — field object (type /Sig trong /Kids), widget annotation có /FT /Sig. Widget tham chiếu Signature dictionary qua key /V (value = signature dictionary). 
  - Signature dictionary (/Sig /V) — object chứa metadata chữ ký: /Type /Sig, /Filter, /SubFilter (ví dụ adbe.pkcs7.detached), /ByteRange (mảng 4 số), /Contents (hex/byte string chứa PKCS#7/CMS), /M (mod date), /Name, /Location, /Reason. /Reference entry có thể dùng theo PDF 2.0 extensions. 
  - /ByteRange — cực kỳ quan trọng: định nghĩa 2 vùng byte (offset + length) trên file để tính digest
  - /Contents không được tham gia digest vì nó chứa chữ ký. Nếu /ByteRange sai thì chữ ký sẽ fail.
  - Incremental updates — chữ ký thường được thêm bằng append (incremental) để bảo toàn bytes gốc; mỗi lần ký thêm tạo một update segment mới. 
  - DSS (PAdES) — dictionary top-level (ví dụ /DSS) chứa /Certs (chain), /CRLs, /OCSPs, /VRI (validation related info) để xác thực lâu dài (LTV). Đây là phần của PAdES profile.

Các object refs:
  - /Root (Catalog) — điểm vào; trỏ tới /Pages và /AcroForm. (điểm lookup đầu tiên). 
  - /Pages (Pages tree node) — tổ chức các trang; dẫn xuống Page object.
  - /Page — chứa /Contents, /Resources, /Annots (widget). Nếu muốn vẽ visual signature, appearance XObject gắn ở đây.
  - /Contents (page stream) — hiển thị nội dung, không chứa chữ ký số (trừ appearance).
  - /Annots[] (widget annotation) — annotation cho field (hiển thị hộp chữ ký, vùng click). Widget trỏ tới field dictionary.
  - /AcroForm — chứa Fields array (tham chiếu tới SigField objects). SigField là field dictionary (tên, kiểu /FT /Sig). 
  - SigField object — định danh field (tên), có /V key -> Signature dictionary (nội dung chữ ký).
  - Signature dictionary (SigDict /V) — chứa /ByteRange, /Contents (PKCS#7), /Filter//SubFilter, metadata. Khi ký, trình ký sẽ viết vào /Contents. Nếu dùng CMS/PKCS#7 thì /SubFilter thường là adbe.pkcs7.detached hoặc adbe.pkcs7.sha1 (các giá trị cũ/ngày xưa). 
  - Incremental update object(s) — phần appended bytes sau cross-reference cũ; giữ lịch sử các thay đổi, cho phép nhiều chữ ký.
  - /DSS (PAdES) — dictionary chứa chứng thư/OCSP/CRL/VRI để hỗ trợ xác thực về lâu dài. (không bắt buộc cho PDF, nhưng bắt buộc nếu muốn PAdES-LTV).


##### 2. Vị trí lưu thời gian ký
######
Vị trí có thể lưu thông tin thời gian:
  - 
