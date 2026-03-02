# 🇻🇳 Mikrotik Vietnam IP List Factory
> Hệ thống tự động hóa thu thập, tối ưu hóa và đóng gói danh sách IP Việt Nam dành cho RouterOS.

![Update Status](https://github.com/VietBac12/my-mikrotik-ip-list/actions/workflows/main.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white)
![Cloudflare](https://img.shields.io/badge/Trigger-Cloudflare_Workers-orange?logo=cloudflare&logoColor=white)
![Mikrotik](https://img.shields.io/badge/Mikrotik-RouterOS_v6%2Fv7-blue?logo=mikrotik&logoColor=white)

## 🚀 Tính năng nổi bật
* **⚡ Tối ưu hóa hiệu năng**: Sử dụng thuật toán **Collapse** để gộp ~4500 dải IP lẻ thành **~1245 dải lớn**, giúp tiết kiệm tài nguyên CPU cho dòng **hEX RB750Gr3**.
* **🛡️ Whitelist thông minh**: Tự động ưu tiên các DNS quốc tế quan trọng (Cloudflare, Google) đi đường nội địa để đạt Ping thấp nhất (1ms - 5ms).
* **🔄 Cập nhật vĩnh viễn**: Kết hợp **Cloudflare Workers** để kích hoạt GitHub Actions, vượt qua giới hạn 60 ngày tự tắt của GitHub.
* **🧹 Sạch sẽ tuyệt đối**: Tự động dọn dẹp Address-list cũ và xóa file tạm `.rsc` trên Mikrotik ngay sau khi nạp xong.

---

## 📐 Sơ đồ kiến trúc (Architecture)

```mermaid
graph TD
    subgraph "🌐 External Triggers"
        A[Cloudflare Workers] -- "Cron: 0 3 * * 1" --> B(GitHub API)
    end

    subgraph "🏗️ GitHub Factory (The Brain)"
        B --> C[GitHub Actions]
        C --> D{Python Script}
        D --> E[APNIC Source]
        D --> F[VNNIC Official]
        D --> G[GeoIP Source]
        E & F & G --> H[Merge & Collapse Algorithm]
        H --> I[vn_ipv4.rsc]
        I --> J[(GitHub Repository)]
    end

    subgraph "🏠 Local Environment (The Client)"
        K[Mikrotik RB750Gr3] -- "Fetch via Raw Link" --> J
        K --> L[Import to Firewall]
        L --> M[Clean Up Temporary Files]
    end

    style A fill:#f9f,stroke:#333,stroke-width:2px
    style K fill:#bbf,stroke:#333,stroke-width:2px
    style I fill:#dfd,stroke:#333,stroke-width:2px

📊 Nguồn dữ liệu tin cậyNguồnLoại dữ liệuTần suấtAPNICRegional Internet RegistryHàng ngàyVNNICBộ Thông tin & Truyền thôngHàng thángGeoIPCommunity-driven (GitHub)Liên tục

🛠️ Hướng dẫn cài đặt
1. Trên GitHub
Fork hoặc Clone Repository này về tài khoản cá nhân.

Tạo một GitHub Personal Access Token (classic) với quyền workflow.

2. Trên Cloudflare Workers (The Trigger)
Sử dụng mã nguồn trong mục workers/trigger.js.

Cài đặt Cron Trigger (0 3 * * 1) để kích hoạt Action vào 3h sáng thứ Hai hàng tuần.

3. Trên Mikrotik (The Client)
Tạo một Script tên update_vn_ip và dán đoạn mã sau (Nhớ thay link bằng link Raw của bạn):

Bash
/tool fetch url="duong dan file cua ban" dst-path=vn.rsc
:delay 15s
/import file-name=vn.rsc
/file remove [find name=vn.rsc]

🛡️ Whitelist mặc định
Danh sách này luôn bao gồm các IP sau để đảm bảo độ trễ thấp nhất và duy trì kết nối ổn định:

1.1.1.1/32 (Cloudflare DNS)

8.8.8.8/32 (Google DNS)

9.9.9.9/32 (Quad9)

✅ Lộ trình phát triển (Roadmap)
[x] Tích hợp nguồn dữ liệu VNNIC chính thống.

[x] Tự động gộp dải IP (Collapse Algorithm).

[x] Kích hoạt ngoại viện qua Cloudflare Workers.

[ ] Gửi báo cáo kết quả qua Telegram Bot.

Dự án được thực hiện bởi VietBac12. Chúc bạn có một đường truyền mượt mà như vũ đạo của NewJeans! 💃
