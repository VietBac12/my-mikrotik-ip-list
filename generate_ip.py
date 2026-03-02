import requests
import ipaddress
import datetime
import re

WHITELIST = ["1.1.1.1/32", "8.8.8.8/32"]

def get_latest_vnnic_url():
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
    print("[!] Khong tim thay file moi, dung link du phong 202508")
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips(url, label):
    print(f"[*] Dang tai du lieu tu {label}...")
    headers = {'User-Agent': 'Mozilla/5.0'}
    networks = []
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line: continue
            if "apnic|VN|ipv4|" in line:
                parts = line.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                networks.append(ipaddress.ip_network(f"{ip}/{prefix}"))
            else:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
                if match:
                    try: networks.append(ipaddress.ip_network(match.group(1)))
                    except: continue
        print(f"    -> Thanh cong: Lay duoc {len(networks)} dai IP.")
        return networks
    except Exception as e:
        print(f"    [!] Loi tai {label}: {e}")
        return []

def main():
    vnnic_url = get_latest_vnnic_url()
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC (Khu vuc)"},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub (GeoIP)"},
        {"url": vnnic_url, "label": "VNNIC (Chinh thong)"}
    ]

    all_nets = []
    for src in sources:
        all_nets.extend(get_ips(src['url'], src['label']))

    for item in WHITELIST:
        all_nets.append(ipaddress.ip_network(item))

    print(f"\n[#] TONG CONG IP THO: {len(all_nets)}")

    # Thuat toan nen IP cho RB750Gr3
    merged_nets = list(ipaddress.collapse_addresses(all_nets))
    print(f"[#] SO LUONG SAU KHI NEN (OPTIMIZED): {len(merged_nets)}")

    with open("vn_ipv4.rsc", "w") as f:
        # Lenh xoa sach list cu de Mikrotik luon sach
        f.write("/ip firewall address-list remove [find list=vn_ipv4]\n")
        for net in merged_nets:
            f.write(f"/ip firewall address-list add list=vn_ipv4 address={net}\n")
    print(f"\n[V] Da xuat file vn_ipv4.rsc thanh cong!")

if __name__ == "__main__":
    main()
