Markdown
# 🇻🇳 Mikrotik Vietnam IP List Factory

Hệ thống tự động hóa thu thập, tối ưu hóa và đóng gói danh sách địa chỉ IP Việt Nam dành riêng cho RouterOS (Mikrotik). 

## 🚀 Tính năng nổi bật
- **Đa nguồn tin cậy:** Kết hợp dữ liệu từ APNIC, VNNIC (Chính thống VN) và GeoIP GitHub.
- **Thuật toán Tối ưu (Collapse):** Tự động gộp các dải IP nhỏ thành dải lớn, giảm từ ~4500 dòng xuống còn ~1245 dòng giúp tiết kiệm tài nguyên CPU cho các dòng router yếu như **hEX RB750Gr3**.
- **Tự động hóa hoàn toàn:** Sử dụng GitHub Actions kết hợp Cloudflare Workers để duy trì cập nhật vĩnh viễn.
- **Sạch sẽ:** Tự động xóa danh sách cũ và dọn dẹp file tạm trên Router sau khi nạp xong.

## 🛠 Cấu trúc hệ thống
1. **GitHub Actions:** Chạy script Python để "sản xuất" file `.rsc`.
2. **Cloudflare Workers:** Đóng vai trò "Trigger" ngoại viện để đảm bảo hệ thống không bị ngủ quên.
3. **Mikrotik Script:** Tự động tải và nạp dữ liệu vào Address-list.

## 📦 Cách sử dụng trên Mikrotik

### Bước 1: Tạo Script
Truy cập **System -> Scripts**, tạo script tên `update_vn_ip` và dán nội dung sau:
(Thay link bằng link Raw của bạn)

```bash
/tool fetch url="LINK_RAW_CUA_BAN" mode=https dst-path=vn.rsc
:delay 15s
/import file-name=vn.rsc
/file remove [find name=vn.rsc]
Bước 2: Lập lịch (Scheduler)
Chạy tự động vào 03:00 sáng thứ Hai hàng tuần:

Bash
/system scheduler add name=sched_vn_ip_update interval=7d start-time=03:00:00 on-event=update_vn_ip
📊 Nguồn dữ liệu
APNIC

VNNIC

Country IP Blocks
Sử dụng Cloudflare Workers để chạy Github Action. Không lo sau 2 tháng Github tắt Action.Tạo Github Token không hết hạn với quyền truy cập workflow là đủ.
export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleScheduledEvent(env));
  },
};

async function handleScheduledEvent(env) {
  // Các thông số lấy từ env (Variables của Cloudflare Worker)
  const GITHUB_TOKEN = env.GH_TOKEN; 
  const GITHUB_USER  = 'VietBac12';
  const GITHUB_REPO  = 'my-mikrotik-ip-list';
  const WORKFLOW_ID  = 'main.yml'; 

  const url = `https://api.github.com/repos/${GITHUB_USER}/${GITHUB_REPO}/actions/workflows/${WORKFLOW_ID}/dispatches`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Cloudflare-Worker-Trigger',
        'X-GitHub-Api-Version': '2022-11-28'
      },
      body: JSON.stringify({ ref: 'main' }),
    });

    if (response.ok) {
      console.log('✅ Đã kích hoạt GitHub Action thành công!');
    } else {
      const error = await response.text();
      console.error('❌ Lỗi API:', error);
    }
  } catch (err) {
    console.error('❌ Lỗi kết nối:', err);
  }
}
Dự án được duy trì bởi VietBac12. Chúc các bạn có một đường truyền mượt mà!
