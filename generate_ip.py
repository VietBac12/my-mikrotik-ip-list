import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH ---
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

# Bộ từ khóa nhận diện nhà mạng (Dựa trên tên tổ chức trong ASN)
ISP_KEYWORDS = {
    "viettel": ["viettel", "military"],
    "vnpt": ["vnpt", "vietnam posts", "vtn"],
    "fpt": ["fpt telecom", "fpt group"],
    "mobifone": ["mobifone", "vms", "vietnam mobile telecom"]
}

def get_latest_vnnic_url():
    # (Hàm tìm link VNNIC giữ nguyên như cũ)
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips_smart(url, label, is_asn_source=False):
    """Xử lý thông minh: Lấy IP tổng và phân loại dựa trên tên nhà mạng"""
    print(f"[*] Đang xử lý {label}...")
    res = {"all": [], "viettel": [], "vnpt": [], "fpt": [], "mobifone": []}
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=35)
        for line in resp.text.splitlines():
            line_raw = line.strip()
            if not line_raw or line_raw.startswith(('#', ';')): continue
            
            # XỬ LÝ NGUỒN ASN (Bản 4 cột: start, end, asn, org)
            if is_asn_source:
                parts = line_raw.split(',')
                if len(parts) >= 4:
                    try:
                        start, end, org_name = parts[0], parts[1], parts[3].lower()
                        summarized = list(ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
                        ))
                        # Phân loại dựa trên tên nhà mạng
                        for isp, keys in ISP_KEYWORDS.items():
                            if any(key in org_name for key in keys):
                                res[isp].extend(summarized)
                                res["all"].extend(summarized) # Cũng thêm vào list tổng VN
                        continue
                    except: continue

            # XỬ LÝ 7 NGUỒN CÒN LẠI (Chỉ lấy IP tổng VN)
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line_raw)
            if match:
                try: res["all"].append(ipaddress.ip_network(match.group(1)))
                except: continue
            elif "apnic|VN|ipv4|" in line_raw:
                parts = line_raw.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                res["all"].append(ipaddress.ip_network(f"{ip}/{prefix}"))
        return res
    except: return res

def main():
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC", "asn": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub Mirror", "asn": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2", "asn": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "asn": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv", "label": "DB-IP", "asn": False},
        {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_vn.netset", "label": "IP2Location", "asn": False},
        {"url": get_latest_vnnic_url(), "label": "VNNIC", "asn": False},
        # ĐÂY LÀ LINK MỚI: Bản 4 cột chứa tên nhà mạng (Global ASN)
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv", "label": "ASN-Full-Data", "asn": True}
    ]

    final = {"vn_ipv4": [], "vn_viettel": [], "vn_vnpt": [], "vn_fpt": [], "vn_mobifone": []}
    for src in sources:
        data = get_ips_smart(src['url'], src['label'], is_asn_source=src['asn'])
        for key in final.keys():
            data_key = key.replace("vn_", "") if key != "vn_ipv4" else "all"
            final[key].extend(data.get(data_key, []))

    for item in WHITELIST: final["vn_ipv4"].append(ipaddress.ip_network(item))

    with open("vn_ipv4.rsc", "w") as f:
        for name, nets in final.items():
            merged = list(ipaddress.collapse_addresses(nets))
            print(f"[#] {name}: {len(merged)} dai IP.")
            f.write(f"/ip firewall address-list remove [find list={name}]\n")
            for n in merged: f.write(f"/ip firewall address-list add list={name} address={n}\n")

if __name__ == "__main__": main()
