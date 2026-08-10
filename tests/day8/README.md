# Day 8 - Multi-surface industrial communication scenarios

Muc tieu ngay 8 la mo rong be mat tan cong tu S7comm sang OPC UA, Web/API, logic-aware va cross-layer, nhung van giu core testbed hien tai. Thu muc nay khong thay the cac kich ban S7 da co; no bo sung catalog, dieu kien thuc hien va runner an toan cho thu thap du lieu.

## Dieu kien can co

1. Moi truong tach biet: PLC/testbed, switch, may thu thap va may chay test nam trong mang lab rieng.
2. Controller reachable tu may nay:
   - S7comm: TCP/102 den `TARGET_IP`.
   - OPC UA: TCP/4840 den `OPC_URL`.
3. OPC UA server tren controller da enable va cho phep cac thao tac can test:
   - Anonymous read/subscription cho cac kich ban benign/discovery/browse.
   - Security policy/certificate trust list neu muon test certificate rejected.
   - Write permission duoc cau hinh ro rang neu muon test write denied/invalid write.
4. Web-SCADA backend dang chay neu test nhom Web/API hoac cross-layer:
   - Mac dinh `WEB_SCADA_API=http://127.0.0.1:8000/api`.
   - Backend dang doc OPC UA tag that va khong dung fake data.
5. Co capture pipeline:
   - `CAPTURE_IFACE` dung interface noi vao lab.
   - dumpcap/tshark/tcpdump chay duoc voi quyen capture.
   - Moi kich ban phai co `scenario_id`, start/end timestamp va label.
6. Co quy trinh an toan/rollback:
   - Snapshot gia tri tag truoc/sau.
   - Khoang cooldown giua cac episode.
   - Stop ngay neu bang tai/process vao trang thai khong an toan.
7. Co tai khoan/role web neu test role violation hoac compromised operator session. Neu chua co auth module, chi ghi nhan API rejected/404/405/501 thay vi gia lap du lieu.

## Chay preflight

```bash
python tests/day8/preflight.py
```

Co the override endpoint:

```bash
TARGET_IP=192.168.210.211 \
OPC_URL=opc.tcp://192.168.210.211:4840 \
WEB_SCADA_API=http://127.0.0.1:8000/api \
python tests/day8/preflight.py
```

## Liet ke kich ban

```bash
python tests/day8/run_day8.py --list
python tests/day8/run_day8.py --group opcua --list
```

## Chay safe runner

Mac dinh runner chi dry-run va in dieu kien, evidence, label.

```bash
python tests/day8/run_day8.py --group opcua
```

Chi cac kich ban `safe_to_execute: true` moi duoc chay khi them `--execute`:

```bash
python tests/day8/run_day8.py --scenario OPCUA_BENIGN_RECONNECT --execute
python tests/day8/run_day8.py --scenario OPCUA_ENDPOINT_DISCOVERY --execute
```

Kich ban co kha nang tac dong quy trinh, write, burst hoac flood duoc danh dau `requires_manual_gate: true`. Runner se khong tu dong thuc thi cac kich ban nay.

## Nhom kich ban

### Nhom A - S7 truyen thong

Giu cac label hien tai: `SCAN_PORT`, `ENUM_TAGS`, `RWRITE_BURST`, `SETPOINT_ATTACK`, `SENSOR_SPOOF`, `STEALTHY_WRITE`, `S7_FLOOD`, `PROTOCOL_FUZZ`.

### Nhom B - OPC UA

Them discovery, browse, subscription/reconnect, invalid/denied write, session burst va certificate rejected.

### Nhom C - Web/API

Chi dung cac dai dien co nguon du lieu that tu backend: login failure, role violation, unauthorized command, invalid parameter, rejected command, excessive request.

### Nhom D - Logic-aware

Dong gop quan trong: gia tri hop le nhung sai ngu canh, sai thoi diem, vi pham chuoi lenh, thay doi setpoint khi fault/maintenance, low-rate drift.

### Nhom E - Cross-layer

The hien tinh moi: tu Web sang OPC UA/PLC, operator session bi compromise, divergence giua log web va trang thai PLC, multi-stage attack.

## Dau ra ky vong

Runner ghi JSON vao `test_results/day8/` gom:

- `scenario_id`
- `group`
- `status`
- `start_time`, `end_time`, `duration_s`
- `preconditions`
- `evidence`
- `notes`

File catalog chinh: `tests/day8/scenarios.yaml`.
