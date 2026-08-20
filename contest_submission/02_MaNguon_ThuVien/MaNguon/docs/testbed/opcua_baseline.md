# OPC UA Baseline — Testbed Băng Tải S7-1500

- **PLC:** Siemens S7-1500 CPU 1516-3 PN/DP
- **Firmware:** V2.9.4
- **IP:** 192.168.210.211
- **OPC UA Endpoint:** opc.tcp://192.168.210.211:4840
- **Security Policy:** None (no security for lab)
- **Ngày kiểm tra:** 2026-07-13
- **Script kiểm tra:** `tests/opcua/check_opcua_client.py`
- **Kết quả:** ✅ Connected, browsed namespace 3, found tags

## Danh sách tag đã browse được

| Key | NodeId | Type |
|-----|--------|------|
| Vat 1 | ns=3;s="Vat 1" | Boolean |
| Vat 2 | ns=3;s="Vat 2" | Boolean |
| Vat 3 | ns=3;s="Vat 3" | Boolean |
| BangTai | ns=3;s="BangTai" | Boolean |
| Nhap | ns=3;s="Nhap" | Int16 |
| HienThi | ns=3;s="HienThi" | Int16 |
| CD1 | ns=3;s="CD1" | Int32 |
| CD2 | ns=3;s="CD2" | Int32 |
| CD3 | ns=3;s="CD3" | Int32 |

## Ghi chú

- OPC UA server đã được activate trên PLC qua TIA Portal
- Không có security policy (None) — phù hợp lab cô lập
- Có thể browse thành công namespace index 3
- asyncua client kết nối và đọc giá trị ổn định
