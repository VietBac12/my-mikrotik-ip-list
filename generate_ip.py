import requests
import ipaddress
import datetime
import re
import json

# --- CẤU HÌNH ---
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

ISP_KEYWORDS = {
    "viettel": ["viettel", "military", "vettel"],
    "vnpt": ["vnpt", "vietnam posts", "vinaphone", "vtn"],
    "fpt": ["fpt telecom", "fpt group", "fpt-as"],
    "mobifone": ["mobifone", "vms", "viet nam mobile telecom"]
}

def get_latest_vnnic_url():
    # Giữ nguyên logic tìm link VNNIC mới nhất
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips_smart(url, label, is_asn_source=False, is_vn_native=False, is_google=False):
    """Xử lý thông minh: Thêm logic parse JSON cho Google"""
    res = {"all": [], "viettel": [], "vnpt": [], "fpt": [], "mobifone": []}
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=35)
        
        # --- PHẦN THÊM MỚI: Xử lý Google JSON ---
        if is_google:
            data = resp.json()
            for item in data.get("prefixes", []):
                if "ipv4Prefix" in item:
                    res["all"].append(ipaddress.ip_network(item["ipv4Prefix"]))
            return res
        # ---------------------------------------

        for line in resp.text.splitlines():
            line_raw = line.strip()
            if not line_raw or line_raw.startswith(('#', ';')): continue
            
            # A. PHÂN LOẠI ISP (Từ nguồn ASN Global)
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

            # B. LẤY IP TỔNG
            if is_vn_native or "VN" in line_raw or "apnic|VN|ipv4|" in line_raw:
                if "apnic|VN|ipv4|" in line_raw:
                    parts = line_raw.split('|')
                    ip, count = parts[3], int(parts[4])
                    prefix = 32 - (count.bit_length() - 1)
                    res["all"].append(ipaddress.ip_network(f"{ip}/{prefix}"))
                    continue
                
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line_raw)
                if match:
                    try: res["all"].append(ipaddress.ip_network(match.group(1)))
                    except: continue
                elif "," in line_raw:
                    parts = line_raw.split(',')
                    try:
                        nets = ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(parts[0].strip()), ipaddress.IPv4Address(parts[1].strip())
                        )
                        res["all"].extend(list(nets))
                    except: continue
        return res
    except: return res

def main():
    sources = [
        # --- THÊM LINK GOOGLE VÀO ĐẦY ---
        {"url": "https://www.gstatic.com/ipranges/goog.json", "label": "Google Official", "asn": False, "native": False, "google": True},
        # -------------------------------
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub VN (Native)", "asn": False, "native": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv", "label": "DB-IP", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_vn.netset", "label": "IP2Location VN (Native)", "asn": False, "native": True},
        {"url": get_latest_vnnic_url(), "label": "VNNIC (Native)", "asn": False, "native": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/refs/heads/main/iptoasn-country/iptoasn-country-ipv4.csv", "label": "iptoasn-country", "asn": False, "native": False},
        #{"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv", "label": "ASN-Source", "asn": True, "native": False}
    ]

    # Thêm GOOGLE_IPS vào danh sách list cuối cùng
    final_lists = {
        "vn_ipv4": [], 
        "vn_viettel": [], 
        "vn_vnpt": [], 
        "vn_fpt": [], 
        "vn_mobifone": [], 
        "vn_isp_all": [],
        "GOOGLE_IPS": [] # Tên list cho MikroTik
    }
    
    print(f"[*] THU THẬP DỮ LIỆU IP - {datetime.datetime.now().strftime('%H:%M:%S')}")
    print("-" * 70)
    for src in sources:
        # Gọi hàm với tham số google
        data = get_ips_smart(src['url'], src['label'], is_asn_source=src['asn'], is_vn_native=src['native'], is_google=src.get('google', False))
        print(f"[*] {src['label']:<25} -> Thành công: {len(data['all']):>5} dải IP.")
        
        # Phân loại: Nếu là Google thì cho vào list riêng, còn lại cho vào VN
        if src.get('google'):
            final_lists["GOOGLE_IPS"].extend(data["all"])
        else:
            final_lists["vn_ipv4"].extend(data["all"])
            final_lists["vn_viettel"].extend(data["viettel"])
            final_lists["vn_vnpt"].extend(data["vnpt"])
            final_lists["vn_fpt"].extend(data["fpt"])
            final_lists["vn_mobifone"].extend(data["mobifone"])
            final_lists["vn_isp_all"].extend(data["viettel"] + data["vnpt"] + data["fpt"] + data["mobifone"])

    for item in WHITELIST: final_lists["vn_ipv4"].append(ipaddress.ip_network(item))

    print("-" * 70)
    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# VN & Google IP List - Ultimate Corrected - Updated: {datetime.datetime.now()}\n")
        f.write("/ip firewall address-list\n") # Viết header 1 lần để file ngắn gọn
        for name, networks in final_lists.items():
            if not networks: continue
            merged = list(ipaddress.collapse_addresses(networks))
            print(f"[#] {name:<12}: {len(merged):>5} dải IP (Nén).")
            f.write(f"remove [find list={name}]\n")
            for net in merged:
                f.write(f"add list={name} address={net}\n")

if __name__ == "__main__": main()
