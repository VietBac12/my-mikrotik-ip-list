import requests
import ipaddress
import datetime
import re

# --- CẤU HÌNH ---
WHITELIST = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32"]

# Bộ từ khóa nhận diện nhà mạng từ dữ liệu ASN
ISP_KEYWORDS = {
    "viettel": ["viettel", "military"],
    "vnpt": ["vnpt", "vietnam posts"],
    "fpt": ["fpt telecom", "fpt group"],
    "mobifone": ["mobifone", "vms", "vietnam mobile telecom"]
}

def get_latest_vnnic_url():
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

def get_ips_categorized(url, label, needs_filter=False):
    """Tải dữ liệu và phân loại ISP dựa trên nội dung dòng (nếu có thông tin ASN)"""
    print(f"[*] Đang lấy dữ liệu từ {label}...")
    data = {"all": [], "viettel": [], "vnpt": [], "fpt": [], "mobifone": []}
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=35)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line_raw = line.strip()
            if not line_raw or line_raw.startswith(('#', ';', 'network')): continue
            
            # 1. Xử lý định dạng RANGE CSV (start,end,info) - Cực kỳ quan trọng để phân loại ISP
            if needs_filter and "VN" in line_raw:
                parts = line_raw.split(',')
                if len(parts) >= 2:
                    try:
                        start_ip, end_ip = parts[0].strip(), parts[1].strip()
                        summarized = list(ipaddress.summarize_address_range(
                            ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip)
                        ))
                        data["all"].extend(summarized)
                        
                        # Phân loại ISP dựa trên thông tin đi kèm trong dòng (nếu có)
                        info = line_raw.lower()
                        for isp, keys in ISP_KEYWORDS.items():
                            if any(key in info for key in keys):
                                data[isp].extend(summarized)
                        continue
                    except: continue

            # 2. Xử lý định dạng CIDR hoặc APNIC Pipe
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line_raw)
            if match:
                try: 
                    net = ipaddress.ip_network(match.group(1))
                    data["all"].append(net)
                except: continue
            elif "apnic|VN|ipv4|" in line_raw:
                parts = line_raw.split('|')
                ip, count = parts[3], int(parts[4])
                prefix = 32 - (count.bit_length() - 1)
                data["all"].append(ipaddress.ip_network(f"{ip}/{prefix}"))
                
        return data
    except Exception as e:
        print(f"    [!] Lỗi tại {label}: {e}")
        return data

def main():
    vn_url = get_latest_vnnic_url()
    
    # ĐÚNG 8 NGUỒN LINK "SỐNG" CỦA BẠN
    sources = [
        {"url": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "label": "APNIC", "filter": False},
        {"url": "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/vn.cidr", "label": "GitHub Mirror", "filter": False},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv", "label": "GeoLite2", "filter": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/iplocate-country/iplocate-country-ipv4.csv", "label": "iplocate-country", "filter": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv", "label": "DB-IP", "filter": True},
        {"url": "https://raw.githubusercontent.com/sapics/ip-location-db/refs/heads/main/iptoasn-country/iptoasn-country-ipv4.csv", "label": "iptoasn-VN", "filter": True},
        {"url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ip2location_country/ip2location_country_vn.netset", "label": "IP2Location", "filter": False},
        {"url": vn_url, "label": "VNNIC", "filter": False}
    ]

    final_lists = {"vn_ipv4": [], "vn_viettel": [], "vn_vnpt": [], "vn_fpt": [], "vn_mobifone": []}
    
    for src in sources:
        res = get_ips_categorized(src['url'], src['label'], needs_filter=src['filter'])
        final_lists["vn_ipv4"].extend(res["all"])
        final_lists["vn_viettel"].extend(res["viettel"])
        final_lists["vn_vnpt"].extend(res["vnpt"])
        final_lists["vn_fpt"].extend(res["fpt"])
        final_lists["vn_mobifone"].extend(res["mobifone"])

    for item in WHITELIST: final_lists["vn_ipv4"].append(ipaddress.ip_network(item))

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("vn_ipv4.rsc", "w") as f:
        f.write(f"# VN IP List - Categorized 4 ISPs - Updated: {now_str}\n")
        for list_name, networks in final_lists.items():
            f.write(f"/ip firewall address-list remove [find list={list_name}]\n")
            merged = list(ipaddress.collapse_addresses(networks))
            print(f"[#] {list_name}: {len(merged)} dải IP.")
            for net in merged:
                f.write(f"/ip firewall address-list add list={list_name} address={net}\n")
            
    print(f"\n[V] Đã xuất file vn_ipv4.rsc thành công với 8 nguồn và 4 nhà mạng!")

if __name__ == "__main__": main()
