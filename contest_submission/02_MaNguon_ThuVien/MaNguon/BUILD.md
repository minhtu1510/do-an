# S7Pwn - Hướng dẫn Build và Deployment

Tài liệu này hướng dẫn các cách build và deploy S7Pwn để chạy trên máy khác.

## Mục lục

1. [Build Executable Windows (PyInstaller)](#1-build-executable-windows-pyinstaller)
2. [Docker Container](#2-docker-container)
3. [Python Package Distribution](#3-python-package-distribution)
4. [Portable ZIP Package](#4-portable-zip-package)

---

## 1. Build Executable Windows (PyInstaller)

### Phương pháp tốt nhất cho: Người dùng không có Python

Tạo file `.exe` độc lập chạy trực tiếp trên Windows mà không cần cài Python.

### Bước 1: Cài đặt PyInstaller

```bash
pip install pyinstaller
```

### Bước 2: Build Executable

```bash
python build_exe.py
```

Script này sẽ:
- ✓ Tự động cài PyInstaller nếu chưa có
- ✓ Build CLI version (`s7pwn.exe`)
- ✓ Build Web GUI version (`s7pwn-webgui.exe`)
- ✓ Tạo launcher scripts (.bat files)
- ✓ Copy documentation
- ✓ Tạo thư mục reports/

### Bước 3: Kết quả

```
dist/s7pwn/
├── s7pwn.exe              # CLI executable
├── s7pwn-webgui.exe       # Web GUI executable
├── s7pwn-cli.bat          # CLI launcher
├── s7pwn-webgui.bat       # Web GUI launcher
├── reports/               # Thư mục báo cáo
├── device_map/            # Device data
├── templates/             # Web templates
├── _internal/             # Dependencies
├── README.md
├── FEATURES.md
├── QUICK_START.md
└── README_DIST.txt        # Hướng dẫn sử dụng
```

### Bước 4: Phân phối

**Cách 1: ZIP Archive**
```bash
# Nén thư mục dist/s7pwn
Compress-Archive -Path dist/s7pwn -DestinationPath S7Pwn-Portable.zip
```

**Cách 2: NSIS Installer (Tùy chọn)**
```bash
# Cài NSIS từ https://nsis.sourceforge.io/
# Build script sẽ tạo installer.nsi
makensis installer.nsi
```

### Sử dụng trên máy đích

1. Giải nén `S7Pwn-Portable.zip`
2. Double-click `s7pwn-cli.bat` (CLI) hoặc `s7pwn-webgui.bat` (Web GUI)
3. Lần đầu chạy có thể chậm (giải nén dependencies)

### Yêu cầu máy đích

- Windows 10/11 (64-bit)
- Administrator privileges (để scan mạng)
- Không cần cài Python
- Không cần cài dependencies

---

## 2. Docker Container

### Phương pháp tốt nhất cho: Cross-platform, Server deployment

Chạy S7Pwn trong container Docker, hoạt động trên Windows, Linux, macOS.

### Bước 1: Build Docker Image

```bash
docker build -t s7pwn:latest .
```

### Bước 2: Chạy Container

**CLI Mode:**
```bash
docker run -it --net=host --privileged s7pwn:latest
```

**Web GUI Mode:**
```bash
docker run -it --net=host --privileged -p 5000:5000 s7pwn:latest python start_webgui.py --host 0.0.0.0 --no-browser
```

**Với volume mapping (để lưu reports):**
```bash
docker run -it --net=host --privileged -v $(pwd)/reports:/app/reports s7pwn:latest
```

### Sử dụng Docker Compose (Khuyến nghị)

**Khởi động Web GUI:**
```bash
docker-compose up s7pwn-web
```

**Khởi động CLI (interactive):**
```bash
docker-compose run --rm s7pwn-cli
```

**Background mode:**
```bash
docker-compose up -d s7pwn-web
docker-compose logs -f s7pwn-web
```

### Export và Import Image

**Export image:**
```bash
docker save s7pwn:latest | gzip > s7pwn-docker.tar.gz
```

**Import trên máy khác:**
```bash
docker load < s7pwn-docker.tar.gz
```

### Yêu cầu máy đích

- Docker installed
- Linux: sudo/root privileges
- Windows: Docker Desktop
- macOS: Docker Desktop

---

## 3. Python Package Distribution

### Phương pháp tốt nhất cho: Developers, Python users

Tạo Python package (wheel) có thể cài đặt bằng pip.

### Bước 1: Build Package

```bash
# Cài build tools
pip install build

# Build package
python -m build
```

Tạo ra:
```
dist/
├── s7pwn-1.0.0-py3-none-any.whl
└── s7pwn-1.0.0.tar.gz
```

### Bước 2: Cài đặt Package

**Từ wheel file:**
```bash
pip install dist/s7pwn-1.0.0-py3-none-any.whl
```

**Từ source:**
```bash
pip install dist/s7pwn-1.0.0.tar.gz
```

**Development mode:**
```bash
pip install -e .
```

### Bước 3: Phân phối

**Cách 1: Chia sẻ file wheel**
```bash
# Copy file .whl sang máy khác
# Cài đặt: pip install s7pwn-1.0.0-py3-none-any.whl
```

**Cách 2: Private PyPI server**
```bash
# Upload lên private PyPI
twine upload --repository-url http://your-pypi-server dist/*
```

**Cách 3: Git repository**
```bash
# Cài trực tiếp từ Git
pip install git+https://github.com/your-repo/S7.Pwn.git
```

### Sử dụng sau khi cài

```bash
# CLI
s7pwn

# Web GUI
s7pwn-webgui
# hoặc
python -m s7pwn.web_gui
```

### Yêu cầu máy đích

- Python 3.9+
- pip
- Các dependencies sẽ được cài tự động

---

## 4. Portable ZIP Package

### Phương pháp tốt nhất cho: Quick deployment, Python available

Tạo package Python portable không cần install.

### Bước 1: Cài Dependencies vào thư mục

```bash
# Tạo thư mục portable
mkdir S7Pwn-Portable
cd S7Pwn-Portable

# Copy source code
xcopy /E /I ..\s7pwn s7pwn
copy ..\start_webgui.py .
copy ..\requirements.txt .
copy ..\*.md .

# Cài dependencies vào vendor/
pip install -r requirements.txt --target vendor/

# Tạo launcher
```

### Bước 2: Tạo Launcher Scripts

**run_cli.bat:**
```batch
@echo off
set PYTHONPATH=%~dp0vendor;%~dp0
python -m s7pwn.cli
pause
```

**run_webgui.bat:**
```batch
@echo off
set PYTHONPATH=%~dp0vendor;%~dp0
python start_webgui.py
pause
```

**run_cli.sh (Linux):**
```bash
#!/bin/bash
export PYTHONPATH="$(dirname $0)/vendor:$(dirname $0)"
python3 -m s7pwn.cli
```

### Bước 3: Nén và phân phối

```bash
Compress-Archive -Path S7Pwn-Portable -DestinationPath S7Pwn-Portable.zip
```

### Yêu cầu máy đích

- Python 3.9+ đã cài
- Không cần pip install
- Giải nén và chạy

---

## So sánh các phương pháp

| Phương pháp | Ưu điểm | Nhược điểm | Kích thước |
|-------------|---------|------------|------------|
| **PyInstaller EXE** | ✓ Không cần Python<br>✓ Dễ sử dụng nhất<br>✓ Click and run | ✗ Chỉ Windows<br>✗ File size lớn<br>✗ Khởi động chậm | ~100-150 MB |
| **Docker** | ✓ Cross-platform<br>✓ Isolated environment<br>✓ Easy deployment | ✗ Cần Docker<br>✗ Overhead<br>✗ Phức tạp hơn | ~500 MB |
| **Python Package** | ✓ Nhỏ gọn nhất<br>✓ Chuẩn Python<br>✓ Dễ update | ✗ Cần Python<br>✗ Dependencies<br>✗ Có thể conflict | ~1-2 MB |
| **Portable ZIP** | ✓ Không cần install<br>✓ Flexible<br>✓ Dễ customize | ✗ Cần Python<br>✗ File size trung bình | ~50-80 MB |

---

## Khuyến nghị sử dụng

### Cho End Users (không biết lập trình):
→ **PyInstaller EXE** (Cách 1)

### Cho IT/DevOps teams:
→ **Docker** (Cách 2)

### Cho Developers:
→ **Python Package** (Cách 3)

### Cho Testing/Demo nhanh:
→ **Portable ZIP** (Cách 4)

---

## Troubleshooting

### Build PyInstaller lỗi

**Lỗi: "ModuleNotFoundError"**
```bash
# Cài lại dependencies
pip install -r requirements.txt
```

**Lỗi: "ImportError" khi chạy .exe**
```bash
# Thêm hidden imports vào build_exe.py
# Trong phần hiddenimports=[], thêm module bị thiếu
```

**File .exe quá lớn:**
```bash
# Sử dụng UPX compression
pip install pyinstaller[encryption]
# Đã được bật trong build_exe.py (upx=True)
```

### Docker lỗi

**Container không scan được mạng:**
```bash
# Phải dùng --net=host và --privileged
docker run -it --net=host --privileged s7pwn:latest
```

**Permission denied:**
```bash
# Trên Linux, cần sudo
sudo docker run ...
```

### Python Package lỗi

**Import error sau khi cài:**
```bash
# Reinstall
pip uninstall s7pwn
pip install --no-cache-dir s7pwn-1.0.0-py3-none-any.whl
```

**Dependencies conflict:**
```bash
# Sử dụng virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux
pip install s7pwn-1.0.0-py3-none-any.whl
```

---

## Testing Build trước khi Deploy

### Test PyInstaller Build

```bash
# After build
cd dist/s7pwn
s7pwn.exe
# Trong CLI: scan, list, help
```

### Test Docker Build

```bash
# Test CLI
docker run -it --rm s7pwn:latest python -m s7pwn.cli
# Gõ: help

# Test Web GUI
docker run -it --rm -p 5000:5000 s7pwn:latest python start_webgui.py --host 0.0.0.0 --no-browser
# Mở browser: http://localhost:5000
```

### Test Python Package

```bash
# Create clean venv
python -m venv test_env
.\test_env\Scripts\activate

# Install
pip install dist/s7pwn-1.0.0-py3-none-any.whl

# Test
s7pwn
s7pwn-webgui --help
```

---

## Checklist trước khi Deploy

- [ ] Test trên máy clean (không có Python/dependencies)
- [ ] Verify tất cả dependencies được include
- [ ] Test network scanning functionality
- [ ] Test Web GUI trên browser khác nhau
- [ ] Verify export reports hoạt động
- [ ] Kiểm tra file size hợp lý
- [ ] Tạo README cho end users
- [ ] Test trên Windows version khác nhau (nếu dùng .exe)
- [ ] Scan với antivirus (có thể false positive)

---

## Security Notes

⚠️ **Antivirus False Positives**

PyInstaller executables thường bị antivirus đánh dấu false positive vì:
- Packed executable behavior
- Network scanning capabilities
- PLC interaction code

**Giải pháp:**
1. Code signing certificate (khuyến nghị cho production)
2. Submit to antivirus vendors for whitelisting
3. Hướng dẫn users add exception
4. Sử dụng Docker thay vì .exe

⚠️ **Network Security**

- Web GUI không có authentication
- Chỉ bind localhost mặc định
- Cẩn thận khi expose ra internet
- Sử dụng VPN/tunnel cho remote access

---

## Support & Updates

Sau khi deploy, users có thể:

**Update PyInstaller build:**
- Download version mới và replace

**Update Docker:**
```bash
docker pull your-registry/s7pwn:latest
docker-compose down && docker-compose up -d
```

**Update Python package:**
```bash
pip install --upgrade s7pwn
```

---

**Tóm lại:** Chọn phương pháp build phù hợp với đối tượng sử dụng và môi trường deployment của bạn!
