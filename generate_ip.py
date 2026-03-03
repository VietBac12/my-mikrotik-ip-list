import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH WHITELIST (Ping 1ms - 5ms cho DNS và dịch vụ quan trọng) ---
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

def get_latest_vnnic_url():
    """Tự động tìm link VNNIC chính thống mới nhất"""
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
                print(f"[+] Tim thay nguon VNNIC: {year_month}")
                return test_url
        except: continue
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips(url, label, needs_filter=False):
    """Trích xuất IP từ mọi định dạng: Pipe, CIDR, và Range CSV"""
    print(f"[*] Dang lay du lieu tu {label}...")
    networks = []
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=30)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', ';', 'network')): continue
            
            # 1. Xử lý APNIC
            if "apnic|VN|ipv4|" in line:
                parts = line.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                networks.append(ipaddress.ip_network(f"{ip}/{prefix}"))
                continue

            # 2. Xử lý RANGE CSV (start,end,VN) - Cho GeoLite2, DB-IP, iptoasn...
            if needs_filter and "VN" in line:
                parts = line.split(',')
                if len(parts) >= 2:
                    try:
                        start_ip, end_ip = parts[0].strip(), parts[1].strip()
                        summarized = ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(start_ip),
                            ipaddress.IPv4Address(end_ip)
                        )
                        networks.extend(list(summarized))
                        continue
                    except: continue

            # 3. Xử lý CIDR (Bắt định dạng x.x.x.x/y)
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
            if match:
                try: networks.append(ipaddress.ip_network(match.group(1)))
                except: continue
                    
        print(f"    -> Thanh cong: {len(networks)} dai IP.")
        return networks
    except Exception as e:
        print(f"    [!] Loi tai {label}: {e}")
        return []

def main():
    vn_url = get_latest_vnnic_url()
    
    # DANH SÁCH 8 NGUỒN "SỐNG" 100% - ĐÃ LOẠI BỎ IPINFO
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC (Chinh thuc)", "filter": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub GeoIP Mirror", "filter": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2 (MaxMind)", "filter": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "filter": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv", "label": "DB-IP (Confirmed Link)", "filter": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/refs/heads/main/iptoasn-country/iptoasn-country-ipv4.csv", "label": "iptoasn-country (Confirmed Link)", "filter": True},
        {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_vn.netset", "label": "IP2Location (Firehol Mirror)", "filter": False},
        {"url": vn_url, "label": "VNNIC (Official)", "filter": False}
    ]

    all_nets = []
    for src in sources:
        all_nets.extend(get_ips(src['url'], src['label'], needs_filter=src['filter']))

    for item in WHITELIST:
        all_nets.append(ipaddress.ip_network(item))

    # Gộp dải IP (Collapse) để hEX Gr3 chạy mượt nhất
    merged_nets = list(ipaddress.collapse_addresses(all_nets))
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# VN IP List - Final 8 Sources - Updated: {now_str}\n")
        f.write("/ip firewall address-list remove [find list=vn_ipv4]\n")
        for net in merged_nets:
            f.write(f"/ip firewall address-list add list=vn_ipv4 address={net}\n")
            
    print(f"\n[#] Tong IP tho: {len(all_nets)}")
    print(f"[#] So luong IP sau khi nen: {len(merged_nets)}")
    print(f"[V] Xuat file vn_ipv4.rsc THANH CONG!")

if __name__ == "__main__":
    main()
