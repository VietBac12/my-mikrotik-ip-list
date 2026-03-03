import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH ---
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

# Bộ từ khóa nhận diện nhà mạng (Dùng cho nguồn ASN Full)
ISP_KEYWORDS = {
    "viettel": ["viettel", "military"],
    "vnpt": ["vnpt", "vietnam posts", "vtn"],
    "fpt": ["fpt telecom", "fpt group"],
    "mobifone": ["mobifone", "vms", "vietnam mobile telecom"]
}

def get_latest_vnnic_url():
    # (Giữ nguyên hàm tìm link VNNIC)
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips_smart(url, label, is_asn_source=False):
    """Xử lý thông minh: Phải có 'VN' cho nguồn tổng và 'Keyword' cho nguồn ISP"""
    print(f"[*] Dang xu ly {label}...")
    res = {"all": [], "viettel": [], "vnpt": [], "fpt": [], "mobifone": []}
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=35)
        for line in resp.text.splitlines():
            line_raw = line.strip()
            if not line_raw or line_raw.startswith(('#', ';')): continue
            
            # A. PHÂN LOẠI ISP (Chỉ từ nguồn ASN-Full)
            if is_asn_source:
                parts = line_raw.split(',')
                if len(parts) >= 4:
                    try:
                        start, end, org_name = parts[0], parts[1], parts[3].lower()
                        # Chỉ xử lý nếu tên tổ chức khớp với ISP Việt Nam
                        for isp, keys in ISP_KEYWORDS.items():
                            if any(key in org_name for key in keys):
                                nets = list(ipaddress.summarize_address_range(
                                    ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
                                ))
                                res[isp].extend(nets)
                                res["all"].extend(nets) # ISP VN chắc chắn là IP VN
                        continue
                    except: continue

            # B. LỌC IP TỔNG HỢP VIỆT NAM (Phải có chữ VN hoặc định dạng VN)
            # 1. Xử lý APNIC (Phải có |VN|ipv4|)
            if "apnic|VN|ipv4|" in line_raw:
                parts = line_raw.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                res["all"].append(ipaddress.ip_network(f"{ip}/{prefix}"))
                continue

            # 2. Xử lý các file CSV/Netset (Phải có chữ VN)
            if "VN" in line_raw:
                # Tìm định dạng CIDR (x.x.x.x/y)
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line_raw)
                if match:
                    try: res["all"].append(ipaddress.ip_network(match.group(1)))
                    except: continue
                # Tìm định dạng Range (start,end)
                elif "," in line_raw:
                    parts = line_raw.split(',')
                    try:
                        nets = ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(parts[0].strip()),
                            ipaddress.IPv4Address(parts[1].strip())
                        )
                        res["all"].extend(list(nets))
                    except: continue
                    
        return res
    except: return res

def main():
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC", "asn": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub VN", "asn": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2", "asn": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "asn": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv", "label": "DB-IP", "asn": False},
        {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_vn.netset", "label": "IP2Location VN", "asn": False},
        {"url": get_latest_vnnic_url(), "label": "VNNIC", "asn": False},
        # Link ASN Full dùng để bóc tách ISP
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv", "label": "ASN-Full-Data", "asn": True}
    ]

    final = {"vn_ipv4": [], "vn_viettel": [], "vn_vnpt": [], "vn_fpt": [], "vn_mobifone": []}
    for src in sources:
        data = get_ips_smart(src['url'], src['label'], is_asn_source=src['asn'])
        final["vn_ipv4"].extend(data["all"])
        final["vn_viettel"].extend(data["viettel"])
        final["vn_vnpt"].extend(data["vnpt"])
        final["vn_fpt"].extend(data["fpt"])
        final["vn_mobifone"].extend(data["mobifone"])

    for item in WHITELIST: final["vn_ipv4"].append(ipaddress.ip_network(item))

    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# VN IP List - Categorized - Updated: {datetime.datetime.now()}\n")
        for name, networks in final.items():
            merged = list(ipaddress.collapse_addresses(networks))
            print(f"[#] {name}: {len(merged)} dai IP.")
            f.write(f"/ip firewall address-list remove [find list={name}]\n")
            for net in merged:
                f.write(f"/ip firewall address-list add list={name} address={net}\n")

if __name__ == "__main__": main()
