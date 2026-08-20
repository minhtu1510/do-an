# ICSScout Portable - Build Instructions

## Xây dựng ứng dụng Portable để chạy từ USB

### 📋 Yêu cầu trước khi build

1. **Python 3.8 trở lên**
```bash
python --version
```

2. **Các dependencies đã cài đặt**
```bash
pip install -r requirements.txt
```

3. **PyInstaller**
```bash
pip install pyinstaller
```

---

## 🚀 Cách 1: Build tự động (Khuyến nghị)

### Bước 1: Chạy build script

```bash
# Linux/Mac
python build_portable.py

# Windows
python build_portable.py
```

Script sẽ tự động:
- ✓ Kiểm tra PyInstaller
- ✓ Clean build directories
- ✓ Build executable
- ✓ Tạo package structure
- ✓ Copy templates và static files
- ✓ Tạo launcher scripts
- ✓ Tạo documentation

### Bước 2: Kết quả

```
ICSScout_Portable/
├── ICSScout.exe (hoặc ICSScout trên Linux)
├── Start_ICSScout.bat (Windows launcher)
├── start_icsscout.sh (Linux launcher)
├── data/ (session data)
├── reports/ (generated reports)
├── sessions/ (saved sessions)
├── _internal/ (dependencies)
└── README.txt
```

### Bước 3: Sử dụng

**Windows:**
1. Copy folder `ICSScout_Portable` vào USB
2. Cắm USB vào máy tính target
3. Right-click `Start_ICSScout.bat` → Run as Administrator
4. Mở browser: http://localhost:5000

**Linux:**
1. Copy folder `ICSScout_Portable` vào USB
2. Mount USB trên máy tính target
3. `sudo ./start_icsscout.sh`
4. Mở browser: http://localhost:5000

---

## 🔧 Cách 2: Build thủ công

### Bước 1: Clean previous builds

```bash
rm -rf build/ dist/
```

### Bước 2: Build với PyInstaller

```bash
pyinstaller icsscout_app.spec --clean
```

### Bước 3: Tạo portable structure

```bash
mkdir -p ICSScout_Portable
cp -r dist/ICSScout/* ICSScout_Portable/
cd ICSScout_Portable
mkdir data reports sessions
```

### Bước 4: Tạo launcher (Windows)

Tạo file `Start_ICSScout.bat`:
```batch
@echo off
title ICSScout
echo Starting ICSScout...
ICSScout.exe --host 127.0.0.1 --port 5000
pause
```

### Bước 5: Tạo launcher (Linux)

Tạo file `start_icsscout.sh`:
```bash
#!/bin/bash
echo "Starting ICSScout..."
./ICSScout --host 127.0.0.1 --port 5000
```

```bash
chmod +x start_icsscout.sh
```

---

## 📦 Build cho các nền tảng khác nhau

### Windows (64-bit)

```bash
pyinstaller icsscout_app.spec --clean
```

### Linux (64-bit)

```bash
pyinstaller icsscout_app.spec --clean
```

### Cross-platform build

**Không thể cross-compile!** Cần build trên từng platform:
- Build trên Windows → Windows executable
- Build trên Linux → Linux executable
- Build trên Mac → Mac executable

---

## 🐛 Troubleshooting

### Lỗi: "No module named 'icsscout'"

**Fix:**
```bash
# Chạy từ project root
cd /path/to/S7.Pwn
python build_portable.py
```

### Lỗi: Templates không được bundle

**Fix:** Kiểm tra `icsscout_app.spec`:
```python
datas=[
    ('icsscout/interfaces/web/templates', 'icsscout/interfaces/web/templates'),
    ('icsscout/interfaces/web/static', 'icsscout/interfaces/web/static'),
]
```

### Lỗi: "Cannot find scapy"

**Fix:** Add vào hidden imports trong spec file:
```python
hiddenimports=[
    'scapy.all',
    'scapy.layers.inet',
    # ...
]
```

### Executable quá lớn (>500MB)

**Giảm size:**
```python
# Trong spec file, exclude không cần:
excludes=[
    'matplotlib',
    'tkinter',
    'PyQt5',
    'test',
    'unittest',
]
```

### Lỗi permission khi chạy từ USB

**Windows:**
- Run as Administrator
- Install Npcap: https://npcap.com/

**Linux:**
```bash
sudo ./start_icsscout.sh
```

---

## 📊 Kích thước dự kiến

| Component | Size |
|-----------|------|
| Executable | 20-50 MB |
| Dependencies | 100-200 MB |
| Total | 150-300 MB |

---

## ✅ Checklist trước khi distribute

- [ ] Test executable trên máy sạch (không có Python)
- [ ] Test network scanning với admin rights
- [ ] Test all features (scan, risk assessment, monitoring)
- [ ] Test session save/load
- [ ] Test report generation
- [ ] Verify README.txt đầy đủ
- [ ] Include Npcap installer (Windows)
- [ ] Test từ USB flash drive

---

## 🎯 Quick Start cho người dùng cuối

1. **Copy vào USB:**
   ```
   ICSScout_Portable/ → USB Drive
   ```

2. **Chạy:**
   - Windows: Right-click `Start_ICSScout.bat` → Run as Administrator
   - Linux: `sudo ./start_icsscout.sh`

3. **Mở browser:**
   ```
   http://localhost:5000
   ```

4. **Sử dụng:**
   - Network Scanner → OT Protocol Scan → Risk Assessment
   - Tất cả data lưu trong folder `data/`
   - Export reports vào folder `reports/`

---

## 📚 Thêm tài liệu

- `README.txt` - Hướng dẫn sử dụng cho end-user
- `requirements.txt` - Python dependencies (reference)
- Original docs trong `docs/` directory

---

## 🔐 Security Notes

- Ứng dụng cần admin/root privileges cho network scanning
- Npcap driver required trên Windows
- Không chứa backdoor hay telemetry
- All data stored locally
- No internet connection required

---

## 💡 Tips

1. **Giảm build time:** Use `--onedir` instead of `--onefile`
2. **Debug issues:** Run với `--debug` flag
3. **Custom port:** `ICSScout.exe --port 8080`
4. **Remote access:** `ICSScout.exe --host 0.0.0.0` (cẩn thận!)

---

## 📞 Support

Issues: https://github.com/trangjackie/S7.Pwn/issues
