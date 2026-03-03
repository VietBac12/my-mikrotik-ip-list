import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH WHITELIST (IP ưu tiên đi đường VN để đạt Ping 1ms - 5ms) ---
# Tích hợp sẵn DNS Cloudflare và Google vào danh sách VN
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
                print(f"[+] Tim thay nguon VNNIC: {year_month}")
                return test_url
        except: continue
    # Link dự phòng nếu không tìm thấy file mới
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips(url, label):
    """Tải và trích xuất IP từ các định dạng APNIC, VNNIC, GitHub, IP2Location"""
    print(f"[*] Dang lay du lieu tu {label}...")
    headers = {'User-Agent': 'Mozilla/5.0'}
    networks = []
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', ';')): continue
            
            # 1. Xử lý định dạng APNIC (apnic|VN|ipv4|...)
            if "apnic|VN|ipv4|" in line:
                parts = line.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                networks.append(ipaddress.ip_network(f"{ip}/{prefix}"))
            
            # 2. Xử lý định dạng CIDR (VNNIC/GitHub/IP2Location) bằng RegEx
            # RegEx này sẽ bắt được dải IP ngay cả khi có chữ "Allow from" của IP2Location
            else:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
                if match:
                    try:
                        networks.append(ipaddress.ip_network(match.group(1)))
                    except: continue
        print(f"    -> Thanh cong: {len(networks)} dai IP.")
        return networks
    except Exception as e:
        print(f"    [!] Loi tai {label}: {e}")
        return []

def main():
    vnnic_url = get_latest_vnnic_url()
    
    # DANH SÁCH NGUỒN GỘP (Đã sửa link IP2Location sang bản Raw CIDR)
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC (Khu vuc)"},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub GeoIP"},
        {"url": "https://raw.githubusercontent.com/ip2location/ip2location-visitor-blocker/master/apache-cidr/VN.txt", "label": "IP2Location (Raw CIDR)"},
        {"url": vnnic_url, "label": "VNNIC (Official)"}
    ]

    all_nets = []
    for src in sources:
        all_nets.extend(get_ips(src['url'], src['label']))

    # Thêm Whitelist vào danh sách tổng
    for item in WHITELIST:
        all_nets.append(ipaddress.ip_network(item))

    print(f"\n[#] Tong so IP thô thu thap duoc: {len(all_nets)}")

    # THUẬT TOÁN TỐI ƯU: Gộp dải (Collapse) để giảm tải CPU cho hEX RB750Gr3
    merged_nets = list(ipaddress.collapse_addresses(all_nets))
    
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("vn_ipv4.rsc", "w") as f:
        # Ghi chú thông tin file
        f.write(f"# Danh sach IP Viet Nam (Tong hop VNNIC + APNIC + IP2Location)\n")
        f.write(f"# San xuat luc: {now_str}\n")
        
        # Lệnh xóa sạch danh sách cũ trên Mikrotik trước khi nạp mới
        f.write("/ip firewall address-list remove [find list=vn_ipv4]\n")
        
        # Ghi từng dải IP đã được tối ưu vào file
        for net in merged_nets:
            f.write(f"/ip firewall address-list add list=vn_ipv4 address={net}\n")
            
    print(f"[#] So luong IP sau khi nen (Collapse): {len(merged_nets)}")
    print(f"[V] Da xuat file vn_ipv4.rsc thanh cong luc {now_str}!")

if __name__ == "__main__":
    main()
