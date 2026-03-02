import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH WHITELIST (IP luôn ưu tiên đi đường Việt Nam) ---
WHITELIST = ["1.1.1.1/32", "8.8.8.8/32"]

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
                print(f"[+] Tim thay nguon VNNIC moi nhat: {year_month}")
                return test_url
        except: continue
    # Link dự phòng nếu không tìm thấy file mới
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips(url, label):
    """Tải và trích xuất IP từ các định dạng APNIC, VNNIC, GitHub"""
    print(f"[*] Dang lay du lieu tu {label}...")
    headers = {'User-Agent': 'Mozilla/5.0'}
    networks = []
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line: continue
            
            # 1. Xu ly APNIC
            if "apnic|VN|ipv4|" in line:
                parts = line.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                networks.append(ipaddress.ip_network(f"{ip}/{prefix}"))
            
            # 2. Xu ly CIDR (VNNIC/GitHub) bang RegEx
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
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC (Khu vuc)"},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub GeoIP"},
        {"url": vnnic_url, "label": "VNNIC (Official)"}
    ]

    all_nets = []
    for src in sources:
        all_nets.extend(get_ips(src['url'], src['label']))

    for item in WHITELIST:
        all_nets.append(ipaddress.ip_network(item))

    print(f"\n[#] Tong so IP thô thu thap duoc: {len(all_nets)}")

    # THUẬT TOÁN TỐI ƯU: Gộp dải (Collapse) cho hEX RB750Gr3
    merged_nets = list(ipaddress.collapse_addresses(all_nets))
    
    # Lấy thời gian hiện tại để tạo sự khác biệt cho file (Timestamp)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("vn_ipv4.rsc", "w") as f:
        # Ghi chú thời gian cập nhật - Giúp GitHub luôn nhận diện đây là file mới
        f.write(f"# Danh sach IP Viet Nam - San xuat luc: {now_str}\n")
        
        # Lenh quan trong: Xoa sach list cu tren Mikrotik truoc khi nap moi
        f.write("/ip firewall address-list remove [find list=vn_ipv4]\n")
        
        for net in merged_nets:
            f.write(f"/ip firewall address-list add list=vn_ipv4 address={net}\n")
            
    print(f"[#] So luong IP sau khi nen: {len(merged_nets)}")
    print(f"[V] Da xuat file vn_ipv4.rsc luc {now_str} thanh cong!")

if __name__ == "__main__":
    main()
