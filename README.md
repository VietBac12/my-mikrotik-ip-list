# 🇻🇳 Mikrotik Vietnam IP List Factory
> Hệ thống tự động hóa thu thập, tối ưu hóa và đóng gói danh sách IP Việt Nam dành cho RouterOS.

## 🚀 Tính năng nổi bật
* **⚡ Tối ưu hóa hiệu năng**: Sử dụng thuật toán **Collapse** để gộp ~4500 dải IP lẻ thành **~1245 dải lớn**, giúp tiết kiệm tài nguyên CPU cho dòng hEX RB750Gr3.
* **🛡️ Whitelist thông minh**: Tự động ưu tiên các DNS quốc tế quan trọng (Cloudflare, Google) đi đường nội địa để đạt Ping thấp nhất (1ms - 5ms).
* **🔄 Cập nhật vĩnh viễn**: Kết hợp Cloudflare Workers để kích hoạt GitHub Actions, vượt qua giới hạn 60 ngày tự tắt của GitHub.
* **🧹 Sạch sẽ tuyệt đối**: Tự động dọn dẹp Address-list cũ và xóa file tạm `.rsc` trên Mikrotik ngay sau khi nạp xong.

---

## ⚙️ Kiến trúc hệ thống
Dự án vận hành theo mô hình 3 lớp tách biệt:
1. **The Factory (GitHub Actions)**: Chạy Python để tổng hợp dữ liệu từ APNIC, VNNIC và GeoIP.
2. **The Trigger (Cloudflare Workers)**: "Đánh thức" Factory hàng tuần qua API để đảm bảo dữ liệu luôn mới.
3. **The Client (Mikrotik)**: Tải file Raw và thực thi lệnh nạp vào Firewall.

### 📊 Nguồn dữ liệu tin cậy
| Nguồn | Loại dữ liệu | Tần suất |
| :--- | :--- | :--- |
| **APNIC** | Regional Internet Registry | Hàng ngày |
| **VNNIC** | Bộ Thông tin & Truyền thông | Hàng tháng |
| **GeoIP** | Community-driven (GitHub) | Liên tục |

---

## 🛠️ Hướng dẫn cài đặt

### 1. Trên GitHub
* Fork hoặc Clone Repository này.
* Tạo một **GitHub Personal Access Token (classic)** với quyền `workflow`.

### 2. Trên Cloudflare Workers (The Trigger)
* Sử dụng mã nguồn trong mục `workers/trigger.js`.
* Cài đặt **Cron Trigger** (`0 3 * * 1`) để kích hoạt Action vào 3h sáng thứ Hai hàng tuần.

### 3. Trên Mikrotik (The Client)
Tạo một Script tên `update_vn_ip` và dán đoạn mã sau:

```bash
/tool fetch url="LINK_RAW_CUA_BAN" dst-path=vn.rsc
:delay 15s
/import file-name=vn.rsc
/file remove [find name=vn.rsc]
