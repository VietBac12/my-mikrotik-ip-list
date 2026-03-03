import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH WHITELIST (IP luôn ưu tiên đi đường Việt Nam - Ping 1ms-5ms) ---
# Thêm DNS Cloudflare và Google để đảm bảo các dịch vụ này luôn chạy "hộ khẩu" VN
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

def get_latest_vnnic_url():
    """Tự động săn tìm link VNNIC mới nhất trong vòng 6 tháng qua"""
    base_url = "https://vnnic.vn/sites/default/files/"
    suffix = "-thongkeipv4vietnam.txt"
    now = datetime.datetime.now()
    
    for i in range(6):
        target_date = now - datetime.timedelta(days=i*30)
        year_month = target_date.strftime("%Y%m")
        test_url = f"{base_url}{year_month}{suffix}"
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.head(test_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                print(f"[+] Tìm thấy nguồn VNNIC: {year_month}")
                return test_url
        except: continue
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips(url, label):
    """Tải và trích xuất IP từ các định dạng khác nhau"""
    print(f"[*] Đang lấy dữ liệu từ {label}...")
    headers = {'User-Agent': 'Mozilla/5.0'}
    networks = []
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'): continue
            
            # 1. Xử lý định dạng APNIC
            if "apnic|VN|ipv4|" in line:
                parts = line.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                networks.append(ipaddress.ip_network(f"{ip}/{prefix}"))
            
            # 2. Xử lý định dạng CIDR (VNNIC/GitHub/IP2Location) bằng RegEx
            else:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
                if match:
                    try:
                        networks.append(ipaddress.ip_network(match.group(1)))
                    except: continue
        print(f"    -> Thành công: {len(networks)} dải IP.")
        return networks
    except Exception as e:
        print(f"    [!] Lỗi tại {label}: {e}")
        return []

def main():
    vnnic_url = get_latest_vnnic_url()
    
    # DANH SÁCH NGUỒN GỘP: Thêm IP2Location (Bản CIDR cho Việt Nam)
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC (Khu vực)"},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub GeoIP"},
        {"url": "https://www.ip2location.com/free/visitor-blocker", "label": "IP2Location Visitor Blocker"},
        {"url": vnnic_url, "label": "VNNIC (Official)"}
    ]

    all_nets = []
    for src in sources:
        all_nets.extend(get_ips(src['url'], src['label']))

    # Thêm Whitelist DNS để tối ưu tốc độ truy cập dịch vụ quốc tế
    for item in WHITELIST:
        all_nets.append(ipaddress.ip_network(item))

    print(f"\n[#] Tổng số IP thô thu thập được: {len(all_nets)}")

    # THUẬT TOÁN TỐI ƯU: Gộp dải (Collapse) để giảm tải cho hEX RB750Gr3
    # Việc gộp hàng nghìn dải IP nhỏ thành các dải lớn cực kỳ quan trọng cho CPU Router
    merged_nets = list(ipaddress.collapse_addresses(all_nets))
    
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# Danh sach IP Viet Nam (VNNIC + APNIC + IP2Location)\n")
        f.write(f"# San xuat luc: {now_str}\n")
        
        # Lệnh xóa danh sách cũ trước khi nạp mới
        f.write("/ip firewall address-list remove [find list=vn_ipv4]\n")
        
        for net in merged_nets:
            f.write(f"/ip firewall address-list add list=vn_ipv4 address={net}\n")
            
    print(f"[#] Số lượng IP sau khi nén: {len(merged_nets)}")
    print(f"[V] Đã xuất file vn_ipv4.rsc thành công!")

if __name__ == "__main__":
    main()
