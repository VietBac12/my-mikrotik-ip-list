import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH ---
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

# Từ khóa nhận diện nhà mạng (Mở rộng từ khóa kỹ thuật)
ISP_KEYWORDS = {
    "viettel": ["viettel", "military", "vettel"],
    "vnpt": ["vnpt", "vietnam posts", "vinaphone", "vtn"],
    "fpt": ["fpt telecom", "fpt group", "fpt-as"],
    "mobifone": ["mobifone", "vms", "viet nam mobile telecom"]
}

def get_latest_vnnic_url():
    """Tự động tìm link VNNIC mới nhất"""
    base_url = "https://vnnic.vn/sites/default/files/"
    suffix = "-thongkeipv4vietnam.txt"
    now = datetime.datetime.now()
    for i in range(6):
        target_date = now - datetime.timedelta(days=i*30)
        year_month = target_date.strftime("%Y%m")
        test_url = f"{base_url}{year_month}{suffix}"
        try:
            resp = requests.head(test_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if resp.status_code == 200: return test_url
        except: continue
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips_smart(url, label, is_asn_source=False, is_vn_native=False):
    """Xử lý linh hoạt: Không lọc 'VN' với nguồn VNNIC/GitHub VN"""
    print(f"[*] Đang xử lý {label}...")
    res = {"all": [], "viettel": [], "vnpt": [], "fpt": [], "mobifone": []}
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=35)
        for line in resp.text.splitlines():
            line_raw = line.strip()
            if not line_raw or line_raw.startswith(('#', ';')): continue
            
            # A. PHÂN LOẠI ISP (Từ nguồn ASN Global - Phải dùng keyword để xác nhận VN)
            if is_asn_source:
                parts = line_raw.split(',')
                if len(parts) >= 4:
                    try:
                        start, end, org_name = parts[0], parts[1], parts[3].lower()
                        for isp, keys in ISP_KEYWORDS.items():
                            if any(key in org_name for key in keys):
                                nets = list(ipaddress.summarize_address_range(
                                    ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
                                ))
                                res[isp].extend(nets)
                                res["all"].extend(nets)
                        continue
                    except: continue

            # B. LẤY IP TỔNG (Phá bỏ bộ lọc 'VN' cho nguồn Native)
            # Chấp nhận dòng nếu: (Nguồn Native VN) HOẶC (Dòng có chữ VN) HOẶC (APNIC VN)
            if is_vn_native or "VN" in line_raw or "apnic|VN|ipv4|" in line_raw:
                # 1. Xử lý APNIC Pipe
                if "apnic|VN|ipv4|" in line_raw:
                    parts = line_raw.split('|')
                    ip, count = parts[3], int(parts[4])
                    prefix = 32 - (count.bit_length() - 1)
                    res["all"].append(ipaddress.ip_network(f"{ip}/{prefix}"))
                    continue
                
                # 2. Xử lý định dạng CIDR (x.x.x.x/y)
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line_raw)
                if match:
                    try: res["all"].append(ipaddress.ip_network(match.group(1)))
                    except: continue
                # 3. Xử lý định dạng Range CSV
                elif "," in line_raw:
                    parts = line_raw.split(',')
                    try:
                        # Chỉ lấy 2 cột đầu nếu là CSV
                        nets = ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(parts[0].strip()), ipaddress.IPv4Address(parts[1].strip())
                        )
                        res["all"].extend(list(nets))
                    except: continue
                    
        return res
    except: return res

def main():
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub VN (Native)", "asn": False, "native": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv", "label": "DB-IP", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_vn.netset", "label": "IP2Location VN (Native)", "asn": False, "native": True},
        {"url": get_latest_vnnic_url(), "label": "VNNIC (Native)", "asn": False, "native": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv", "label": "ASN-Source", "asn": True, "native": False}
    ]

    final = {"vn_ipv4": [], "vn_viettel": [], "vn_vnpt": [], "vn_fpt": [], "vn_mobifone": []}
    for src in sources:
        data = get_ips_smart(src['url'], src['label'], is_asn_source=src['asn'], is_vn_native=src['native'])
        final["vn_ipv4"].extend(data["all"])
        final["vn_viettel"].extend(data["viettel"])
        final["vn_vnpt"].extend(data["vnpt"])
        final["vn_fpt"].extend(data["fpt"])
        final["vn_mobifone"].extend(data["mobifone"])

    for item in WHITELIST: final["vn_ipv4"].append(ipaddress.ip_network(item))

    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# VN IP List - Corrected Native Sources - Updated: {datetime.datetime.now()}\n")
        for name, networks in final.items():
            merged = list(ipaddress.collapse_addresses(networks))
            print(f"[#] {name}: {len(merged)} dai IP.")
            f.write(f"/ip firewall address-list remove [find list={name}]\n")
            for net in merged:
                f.write(f"/ip firewall address-list add list={name} address={net}\n")

if __name__ == "__main__": main()
