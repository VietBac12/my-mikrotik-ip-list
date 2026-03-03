import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH WHITELIST (Ưu tiên đi đường VN để đạt Ping 1ms - 5ms) ---
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

def get_latest_vnnic_url():
    """Tìm link VNNIC mới nhất trong vòng 6 tháng"""
    base_url = "https://vnnic.vn/sites/default/files/"
    suffix = "-thongkeipv4vietnam.txt"
    now = datetime.datetime.now()
    for i in range(6):
        target_date = now - datetime.timedelta(days=i*30)
        year_month = target_date.strftime("%Y%m")
        test_url = f"{base_url}{year_month}{suffix}"
        try:
            resp = requests.head(test_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if resp.status_code == 200:
                print(f"[+] Tìm thấy nguồn VNNIC: {year_month}")
                return test_url
        except: continue
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips(url, label, needs_filter=False):
    """Tải và trích xuất IP (Hỗ trợ APNIC, CIDR, và IP Range CSV)"""
    print(f"[*] Đang lấy dữ liệu từ {label}...")
    networks = []
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=30)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', ';', 'network')): continue
            
            # 1. Xử lý APNIC (apnic|VN|ipv4|...)
            if "apnic|VN|ipv4|" in line:
                parts = line.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                networks.append(ipaddress.ip_network(f"{ip}/{prefix}"))
                continue

            # 2. Xử lý định dạng RANGE CSV (start_ip,end_ip,VN)
            if needs_filter and "," in line and "VN" in line:
                parts = line.split(',')
                if len(parts) >= 3:
                    try:
                        start_ip, end_ip = parts[0].strip(), parts[1].strip()
                        # Chẻ dải IP thành các CIDR chuẩn cho Mikrotik
                        summarized = ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(start_ip),
                            ipaddress.IPv4Address(end_ip)
                        )
                        networks.extend(list(summarized))
                        continue
                    except: continue

            # 3. Xử lý định dạng CIDR (VNNIC, GitHub VN)
            if not needs_filter or (needs_filter and "VN" in line):
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
                if match:
                    try: networks.append(ipaddress.ip_network(match.group(1)))
                    except: continue
                    
        print(f"    -> Thành công: {len(networks)} dải IP.")
        return networks
    except Exception as e:
        print(f"    [!] Lỗi tại {label}: {e}")
        return []

def main():
    vnnic_url = get_latest_vnnic_url()
    
    # DANH SÁCH 5 NGUỒN GỘP: 
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC (Chính thức)", "filter": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub GeoIP Mirror", "filter": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/refs/heads/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2 (MaxMind)", "filter": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/refs/heads/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "filter": True},
        {"url": vnnic_url, "label": "VNNIC (Official)", "filter": False}
    ]

    all_nets = []
    for src in sources:
        all_nets.extend(get_ips(src['url'], src['label'], needs_filter=src['filter']))

    for item in WHITELIST:
        all_nets.append(ipaddress.ip_network(item))

    print(f"\n[#] Tổng số IP thô thu thập được: {len(all_nets)}")

    # THUẬT TOÁN TỐI ƯU: Gộp dải (Collapse) để hEX Gr3 chạy mượt nhất
    merged_nets = list(ipaddress.collapse_addresses(all_nets))
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# VN IP List - Multi-Source (GeoLite2+iplocate+VNNIC) - Updated: {now_str}\n")
        f.write("/ip firewall address-list remove [find list=vn_ipv4]\n")
        for net in merged_nets:
            f.write(f"/ip firewall address-list add list=vn_ipv4 address={net}\n")
            
    print(f"[#] Số lượng IP sau khi nén (Collapse): {len(merged_nets)}")
    print(f"[V] Đã xuất file vn_ipv4.rsc thành công!")

if __name__ == "__main__":
    main()
