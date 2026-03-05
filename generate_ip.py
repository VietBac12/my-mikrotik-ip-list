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
    # Link VNNIC mà bạn đã cung cấp
    return "https://vnnic.vn/sites/default/files/202508-thongkeipv4vietnam.txt"

def get_ips_smart(url, label, is_asn_source=False, is_vn_native=False, is_google=False):
    res = {"all": [], "viettel": [], "vnpt": [], "fpt": [], "mobifone": []}
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=35)
        
        # 1. XỬ LÝ GOOGLE JSON (MỚI)
        if is_google:
            data = resp.json()
            for item in data.get("prefixes", []):
                if "ipv4Prefix" in item:
                    res["all"].append(ipaddress.ip_network(item["ipv4Prefix"]))
            return res

        for line in resp.text.splitlines():
            line_raw = line.strip()
            if not line_raw or line_raw.startswith(('#', ';')): continue
            
            # 2. PHÂN LOẠI ISP (TỪ ASN SOURCE)
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

            # 3. LẤY IP TỔNG (FIX LỖI 0 DẢI IP)
            is_matched = False
            
            # A. Ưu tiên APNIC Pipe
            if "apnic|VN|ipv4|" in line_raw:
                parts = line_raw.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                res["all"].append(ipaddress.ip_network(f"{ip}/{prefix}"))
                is_matched = True

            # B. Xử lý CIDR (Dành cho GitHub VN Native, IP2Location, VNNIC)
            if not is_matched and (is_vn_native or "VN" in line_raw):
                match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})', line_raw)
                if match:
                    try:
                        res["all"].append(ipaddress.ip_network(match.group(1)))
                        is_matched = True
                    except: pass

            # C. Xử lý CSV Range (GeoLite2, iplocate, DB-IP)
            if not is_matched and "," in line_raw:
                parts = line_raw.split(',')
                try:
                    # Thử xem có phải dải IP (Start, End) không
                    nets = ipaddress.summarize_address_range(
                        ipaddress.IPv4Address(parts[0].strip()), ipaddress.IPv4Address(parts[1].strip())
                    )
                    res["all"].extend(list(nets))
                    is_matched = True
                except: pass
            
            # D. Catch-all cho Native (Tự động parse nếu dòng chỉ có IP)
            if not is_matched and is_vn_native:
                try:
                    res["all"].append(ipaddress.ip_network(line_raw, strict=False))
                except: pass

        return res
    except: return res

def main():
    # ĐẦY ĐỦ 100% CÁC NGUỒN CỦA BẠN
    sources = [
        {"url": "https://www.gstatic.com/ipranges/goog.json", "label": "Google Official", "asn": False, "native": False, "google": True},
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub VN (Native)", "asn": False, "native": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv", "label": "DB-IP", "asn": False, "native": False},
        {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_vn.netset", "label": "IP2Location VN (Native)", "asn": False, "native": True},
        {"url": get_latest_vnnic_url(), "label": "VNNIC (Native)", "asn": False, "native": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/refs/heads/main/iptoasn-country/iptoasn-country-ipv4.csv", "label": "iptoasn-country", "asn": False, "native": False},
    ]

    final_lists = {"vn_ipv4": [], "vn_viettel": [], "vn_vnpt": [], "vn_fpt": [], "vn_mobifone": [], "GOOGLE_IPS": []}
    
    print(f"[*] THU THẬP DỮ LIỆU IP - {datetime.datetime.now().strftime('%H:%M:%S')}")
    print("-" * 70)
    for src in sources:
        data = get_ips_smart(src['url'], src['label'], is_asn_source=src.get('asn', False), is_vn_native=src.get('native', False), is_google=src.get('google', False))
        print(f"[*] {src['label']:<25} -> Thành công: {len(data['all']):>5} dải IP.")
        
        if src.get('google'):
            final_lists["GOOGLE_IPS"].extend(data["all"])
        else:
            final_lists["vn_ipv4"].extend(data["all"])
            final_lists["vn_viettel"].extend(data["viettel"])
            final_lists["vn_vnpt"].extend(data["vnpt"])
            final_lists["vn_fpt"].extend(data["fpt"])
            final_lists["vn_mobifone"].extend(data["mobifone"])

    for item in WHITELIST: final_lists["vn_ipv4"].append(ipaddress.ip_network(item))

    print("-" * 70)
    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# VN & Google IP List - Ultimate - Updated: {datetime.datetime.now()}\n")
        f.write("/ip firewall address-list\n")
        for name, networks in final_lists.items():
            if not networks: continue
            merged = list(ipaddress.collapse_addresses(networks))
            print(f"[#] {name:<12}: {len(merged):>5} dải IP (Nén).")
            f.write(f"remove [find list={name}]\n")
            for net in merged:
                f.write(f"add list={name} address={net}\n")

if __name__ == "__main__": main()
