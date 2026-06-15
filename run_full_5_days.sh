#!/bin/bash

# ==============================================================================
# KỊCH BẢN TỰ ĐỘNG THU THẬP VÀ GHÉP DỮ LIỆU TESTBED 5 NGÀY (CHUẨN DATASENSE)
# Hướng dẫn chạy: bash run_full_5_days.sh
# ==============================================================================

TARGET_IP="192.168.1.10"

run_day() {
    DAY_NUM=$1
    PHASES=$2
    
    echo "=========================================================="
    echo " BẮT ĐẦU THU THẬP DỮ LIỆU NGÀY $DAY_NUM"
    echo " CÁC KỊCH BẢN (PHASES): $PHASES"
    echo "=========================================================="
    
    # 1. Bật Process Logger (Lớp Vật lý) chạy ngầm trong background (&)
    PROCESS_LOG="day${DAY_NUM}_process.csv"
    echo "[*] Đang bật Process Logger ghi vào $PROCESS_LOG..."
    python log_tags.py --target $TARGET_IP --output $PROCESS_LOG &
    PROCESS_PID=$!
    
    # Đợi 2 giây cho Process Logger khởi động kết nối tới PLC
    sleep 2
    
    # 2. Bật Network Collector (Lớp Mạng + DPI + Tool Tấn công)
    DATASET_DIR="dataset_day${DAY_NUM}"
    echo "[*] Đang chạy các kịch bản mạng và tự động tấn công..."
    # Thằng này chạy xong các phase nó sẽ tự động gộp thành 1 file labeled_dataset_...csv
    python collect_dataset.py --target $TARGET_IP --phase $PHASES --output $DATASET_DIR
    
    # 3. Tắt Process Logger (Vì lớp mạng đã chạy xong)
    echo "[*] Đã chạy xong kịch bản mạng. Đang tắt Process Logger..."
    kill -SIGINT $PROCESS_PID
    wait $PROCESS_PID 2>/dev/null
    
    # 4. Tìm file Network CSV vừa được sinh ra (file mới nhất)
    NET_CSV=$(ls -t ${DATASET_DIR}/labeled_dataset_*.csv 2>/dev/null | head -n 1)
    
    if [ -n "$NET_CSV" ] && [ -f "$NET_CSV" ]; then
        FINAL_CSV="final_dataset_day${DAY_NUM}.csv"
        echo "[*] Đang tiến hành ghép nối dữ liệu (Data Integration)..."
        # Bắt đầu gọi file preprocess ghép nối
        python preprocess_pipeline.py --net "$NET_CSV" --phys $PROCESS_LOG --out $FINAL_CSV
        echo "[+] Đã hoàn thành Ngày $DAY_NUM! File cuối cùng (AI Dataset): $FINAL_CSV"
    else
        echo "[!] Lỗi: Không tìm thấy file mạng CSV trong $DATASET_DIR. Kiểm tra lại kết nối PLC hoặc tcpdump!"
    fi
    echo ""
}

# --- BẮT ĐẦU THỰC THI 5 NGÀY ---

# NGÀY 1: Đường cơ sở (Chỉ chạy Normal)
run_day 1 "normal"

# NGÀY 2: Do thám mạng và dò thẻ nhớ
run_day 2 "normal,scan,enum_tags"

# NGÀY 3: Tấn công Toàn vẹn (Ghi rác liên tục và ghi giả mạo)
run_day 3 "normal,rwrite,spoof_constant"

# NGÀY 4: Tấn công Sẵn sàng (Xả TCP Flood và Fuzzing)
run_day 4 "normal,flood,fuzz"

# NGÀY 5: Tấn công Phá hoại (Phát lại lệnh và Dừng CPU)
run_day 5 "normal,replay,cpu_control"

echo "=========================================================="
echo " ĐÃ HOÀN THÀNH TOÀN BỘ CHIẾN DỊCH 5 NGÀY!"
echo " Các file final_dataset_day1.csv -> day5.csv đã sẵn sàng đưa vào Train Model."
echo "=========================================================="
