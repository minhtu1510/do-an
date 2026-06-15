import argparse
from collect_dataset import extract_flow_features_from_pcap

def main():
    parser = argparse.ArgumentParser(description="Trích xuất đặc trưng DPI từ file PCAP có sẵn")
    parser.add_argument("--pcap", required=True, help="Đường dẫn file PCAP đã bắt")
    parser.add_argument("--target", required=True, help="IP của PLC")
    parser.add_argument("--out", required=True, help="Đường dẫn file CSV đầu ra")
    args = parser.parse_args()

    print(f"[*] Đang đọc file PCAP: {args.pcap}")
    print("[*] Quá trình này có thể mất vài phút tùy dung lượng file...")
    
    # Label set to 'MIXED' vì file PCAP chứa cả Normal và Attack, 
    # nhãn thực sự sẽ được gán lại ở bước Preprocess dựa trên timeline
    rows = extract_flow_features_from_pcap(args.pcap, "MIXED", args.out, args.target, 1.0)
    
    print(f"[+] Hoàn tất! Đã trích xuất {rows} dòng dữ liệu (DPI + Mạng) ra file {args.out}")

if __name__ == "__main__":
    main()
