import requests
import ipaddress

# --- CẤU HÌNH WHITELIST ---
WHITELIST = [
    "1.1.1.1/32",
    "8.8.8.8/32"
]

def get_ips(url, label):
    print(f"Dang lay du lieu tu {label}...")
    # Thêm headers để tránh bị server VNNIC chặn Bot
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        networks = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line: continue
            
            # Xử lý định dạng APNIC
            if "apnic|VN|ipv4|" in line:
                parts = line.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                networks.append(ipaddress.ip_network(f"{ip}/{prefix}"))
                continue
            
            # Xử lý định dạng CIDR (VNNIC và GitHub)
            if '/' in line and not line.startswith('#'):
                try:
                    # Lọc lấy phần IP/CIDR nếu dòng có chứa thông tin khác
                    cidr = line.split()[0] 
                    networks.append(ipaddress.ip_network(cidr))
                except:
                    continue
        return networks
    except Exception as e:
        print(f"Loi khi tai {label}: {e}")
        return []

def main():
    # Danh sách 3 nguồn dữ liệu quan trọng
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC (Khu vuc)"},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub (GeoIP)"},
        {"url": "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt", "label": "VNNIC (Chinh thong)"}
    ]

    all_nets = []
    for src in sources:
        all_nets.extend(get_ips(src['url'], src['label']))

    for item in WHITELIST:
        all_nets.append(ipaddress.ip_network(item))

    print(f"Tong so dai IP thu thap: {len(all_nets)}")

    # THUẬT TOÁN GỘP DẢI (Collapse): Giúp RB750Gr3 tra cứu nhanh hơn
    merged_nets = list(ipaddress.collapse_addresses(all_nets))
    print(f"So luong dai IP sau khi gop: {len(merged_nets)}")

    # Xuất file .rsc cho Mikrotik
    with open("vn_ipv4.rsc", "w") as f:
        f.write("/ip firewall address-list\n")
        # Xóa các IP cũ có comment VN để nạp mới mà không bị rác
        f.write("remove [find list=vn_ipv4 comment=\"VN\"]\n")
        for net in merged_nets:
            f.write(f"add list=vn_ipv4 address={net} comment=\"VN\"\n")

if __name__ == "__main__":
    main()
