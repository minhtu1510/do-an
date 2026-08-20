import json
import os

def create_cell(cell_type, source):
    if cell_type == "code":
        return {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": source
        }
    else:
        return {
            "cell_type": "markdown",
            "metadata": {},
            "source": source
        }

notebook = {
    "cells": [],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "codemirror_mode": {"name": "ipython", "version": 3},
            "file_extension": ".py",
            "mimetype": "text/x-python",
            "name": "python",
            "nbconvert_exporter": "python",
            "pygments_lexer": "ipython3",
            "version": "3.8.0"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

cells_data = [
    ("markdown", [
        "# Huấn luyện Mô hình Học máy (Machine Learning) cho Dữ liệu mạng ICS\n",
        "Notebook này thực hiện việc:\n",
        "1. Gộp tập dữ liệu **Train** (Ngày 1 đến Ngày 5) và tập **Test** (Ngày 6).\n",
        "2. Tiền xử lý dữ liệu chuẩn chỉ (Xóa cột Metadata, lấp giá trị NaN).\n",
        "3. Xóa các Feature hằng số (variance = 0) và Feature tương quan cao (> 0.98).\n",
        "4. Chuẩn hóa dữ liệu bằng `StandardScaler`.\n",
        "5. Huấn luyện bằng `RandomForestClassifier` và `MLPClassifier`.\n",
        "6. Vẽ biểu đồ Feature Importances."
    ]),
    ("code", [
        "import pandas as pd\n",
        "import numpy as np\n",
        "import matplotlib.pyplot as plt\n",
        "import seaborn as sns\n",
        "from sklearn.preprocessing import StandardScaler\n",
        "from sklearn.ensemble import RandomForestClassifier\n",
        "from sklearn.neural_network import MLPClassifier\n",
        "from sklearn.metrics import classification_report, confusion_matrix\n",
        "\n",
        "# Tùy chỉnh hiển thị pandas để xem được nhiều cột\n",
        "pd.set_option('display.max_columns', None)\n",
        "import warnings\n",
        "warnings.filterwarnings('ignore')"
    ]),
    ("markdown", [
        "## 1. Load Dữ liệu (Load Data)"
    ]),
    ("code", [
        "# --- CẬP NHẬT ĐƯỜNG DẪN TẠI ĐÂY NẾU CẦN ---\n",
        "train_files = [\n",
        "    'final_dataset_day1.csv',\n",
        "    'final_dataset_day2.csv',\n",
        "    'final_dataset_day3.csv',\n",
        "    'final_dataset_day4.csv',\n",
        "    'final_dataset_day5.csv'\n",
        "]\n",
        "\n",
        "test_file = 'final_dataset_day6.csv'\n",
        "\n",
        "def load_data(files):\n",
        "    dfs = []\n",
        "    for f in files:\n",
        "        try:\n",
        "            df = pd.read_csv(f, low_memory=False)\n",
        "            dfs.append(df)\n",
        "            print(f\"Đã tải {f}: shape = {df.shape}\")\n",
        "        except Exception as e:\n",
        "            print(f\"Không thể tải file {f} (có thể sai đường dẫn): {e}\")\n",
        "    if dfs:\n",
        "        return pd.concat(dfs, ignore_index=True)\n",
        "    else:\n",
        "        print(\"CẢNH BÁO: Không tìm thấy file CSV nào!\")\n",
        "        return pd.DataFrame()\n",
        "\n",
        "print(\"--- ĐANG TẢI TẬP TRAIN (DAY 1-5) ---\")\n",
        "df_train = load_data(train_files)\n",
        "print(\"\\n--- ĐANG TẢI TẬP TEST (DAY 6) ---\")\n",
        "df_test = load_data([test_file])\n",
        "\n",
        "print(\"\\nTổng kích thước Train:\", df_train.shape)\n",
        "print(\"Tổng kích thước Test:\", df_test.shape)"
    ]),
    ("markdown", [
        "## 2. Tiền xử lý (Preprocessing) - Xóa Metadata & Tạo Label nhị phân"
    ]),
    ("code", [
        "# Các cột metadata không dùng để train\n",
        "metadata_cols = [\n",
        "    'window_start_ms', 'window_end_ms', 'plc_ip', 'capture_role',\n",
        "    'top_src_ip', 'top_dst_ip', 'top_protocol', 'capture_source', 'decode_level'\n",
        "]\n",
        "\n",
        "def preprocess_basic(df):\n",
        "    if df.empty: return df, None\n",
        "    \n",
        "    # Xóa các cột metadata nếu có\n",
        "    cols_to_drop = [c for c in metadata_cols if c in df.columns]\n",
        "    df = df.drop(columns=cols_to_drop)\n",
        "    \n",
        "    # Tách X và y\n",
        "    if 'label' in df.columns:\n",
        "        # Chuyển label thành nhị phân: BENIGN = 0, Các nhãn Tấn Công = 1\n",
        "        y = (df['label'] != 'BENIGN').astype(int)\n",
        "        X = df.drop(columns=['label'])\n",
        "    else:\n",
        "        y = None\n",
        "        X = df\n",
        "        \n",
        "    # Fill giá trị Infinity bằng NaN, sau đó fill NaN bằng 0\n",
        "    X = X.replace([np.inf, -np.inf], np.nan)\n",
        "    X = X.fillna(0)\n",
        "    \n",
        "    # Chuyển tất cả data về dạng số thực (float)\n",
        "    X = X.astype(float)\n",
        "    \n",
        "    return X, y\n",
        "\n",
        "X_train, y_train = preprocess_basic(df_train)\n",
        "X_test, y_test = preprocess_basic(df_test)\n",
        "\n",
        "print(\"X_train shape:\", X_train.shape)\n",
        "print(\"X_test shape:\", X_test.shape)"
    ]),
    ("markdown", [
        "## 3. Lọc Features rác (Hằng số & Tương quan cao)"
    ]),
    ("code", [
        "# 3.1: XÓA CỘT HẰNG SỐ (Variance = 0)\n",
        "print(\"Đang lọc các Feature hằng số (không có sự thay đổi)...\")\n",
        "constant_columns = [col for col in X_train.columns if X_train[col].nunique() <= 1]\n",
        "print(f\"-> Đã xóa {len(constant_columns)} cột hằng số.\")\n",
        "\n",
        "X_train = X_train.drop(columns=constant_columns)\n",
        "X_test = X_test.drop(columns=[c for c in constant_columns if c in X_test.columns])\n",
        "\n",
        "# Cân bằng lại cột giữa Train và Test (đề phòng Test bị thiếu tính năng nào đó)\n",
        "missing_cols = set(X_train.columns) - set(X_test.columns)\n",
        "for c in missing_cols:\n",
        "    X_test[c] = 0\n",
        "X_test = X_test[X_train.columns]\n",
        "\n",
        "# 3.2: XÓA CỘT TƯƠNG QUAN CAO (Pearson > 0.98)\n",
        "print(\"\\nĐang tính toán Ma trận tương quan (Correlation Matrix). Quá trình này có thể tốn vài phút...\")\n",
        "corr_matrix = X_train.corr().abs()\n",
        "\n",
        "# Chọn nửa trên (upper triangle) của ma trận tương quan\n",
        "upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))\n",
        "\n",
        "# Tìm các feature có tương quan > 0.98\n",
        "to_drop = [column for column in upper.columns if any(upper[column] > 0.98)]\n",
        "print(f\"-> Phát hiện và xóa {len(to_drop)} cột có tương quan quá cao (bị trùng lặp thông tin).\")\n",
        "\n",
        "X_train = X_train.drop(columns=to_drop)\n",
        "X_test = X_test.drop(columns=to_drop)\n",
        "\n",
        "print(\"\\nX_train SAU KHI LỌC:\", X_train.shape)\n",
        "print(\"X_test SAU KHI LỌC:\", X_test.shape)"
    ]),
    ("markdown", [
        "## 4. Chuẩn hóa dữ liệu (Standard Scaling)"
    ]),
    ("code", [
        "scaler = StandardScaler()\n",
        "X_train_scaled = scaler.fit_transform(X_train)\n",
        "X_test_scaled = scaler.transform(X_test)\n",
        "\n",
        "print(\"Chuẩn hóa thành công! (Mean ~ 0, Std ~ 1)\")"
    ]),
    ("markdown", [
        "## 5. Train & Evaluate bằng Multi-Layer Perceptron (MLP)"
    ]),
    ("code", [
        "print(\"Đang huấn luyện mô hình Mạng Nơ-ron (MLP)... Vui lòng đợi.\")\n",
        "mlp = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=200, random_state=42, early_stopping=True)\n",
        "mlp.fit(X_train_scaled, y_train)\n",
        "print(\"Huấn luyện xong!\")\n",
        "\n",
        "print(\"\\n--- KẾT QUẢ DỰ ĐOÁN TRÊN TẬP TEST (DAY 6) ---\")\n",
        "y_pred_mlp = mlp.predict(X_test_scaled)\n",
        "print(classification_report(y_test, y_pred_mlp, digits=4))\n",
        "\n",
        "cm_mlp = confusion_matrix(y_test, y_pred_mlp)\n",
        "sns.heatmap(cm_mlp, annot=True, fmt='d', cmap='Blues')\n",
        "plt.title('Confusion Matrix - MLP')\n",
        "plt.ylabel('Actual Label')\n",
        "plt.xlabel('Predicted Label')\n",
        "plt.show()"
    ]),
    ("markdown", [
        "## 6. Train & Evaluate bằng Random Forest (RF)"
    ]),
    ("code", [
        "print(\"Đang huấn luyện mô hình Rừng ngẫu nhiên (Random Forest)... Vui lòng đợi.\")\n",
        "rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)\n",
        "rf.fit(X_train_scaled, y_train)\n",
        "print(\"Huấn luyện xong!\")\n",
        "\n",
        "print(\"\\n--- KẾT QUẢ DỰ ĐOÁN TRÊN TẬP TEST (DAY 6) ---\")\n",
        "y_pred_rf = rf.predict(X_test_scaled)\n",
        "print(classification_report(y_test, y_pred_rf, digits=4))\n",
        "\n",
        "cm_rf = confusion_matrix(y_test, y_pred_rf)\n",
        "sns.heatmap(cm_rf, annot=True, fmt='d', cmap='Greens')\n",
        "plt.title('Confusion Matrix - Random Forest')\n",
        "plt.ylabel('Actual Label')\n",
        "plt.xlabel('Predicted Label')\n",
        "plt.show()"
    ]),
    ("markdown", [
        "## 7. Trực quan hóa Feature Importances (Random Forest)"
    ]),
    ("code", [
        "importances = pd.Series(rf.feature_importances_, index=X_train.columns)\n",
        "top_features = importances.sort_values(ascending=False).head(20)\n",
        "\n",
        "plt.figure(figsize=(10, 8))\n",
        "sns.barplot(x=top_features.values, y=top_features.index, palette='viridis')\n",
        "plt.title('Top 20 Features Quan Trọng Nhất Theo Phân Loại Của Random Forest')\n",
        "plt.xlabel('Độ quan trọng (Importance Score)')\n",
        "plt.ylabel('Tên Feature')\n",
        "plt.tight_layout()\n",
        "plt.show()"
    ])
]

for cell_type, source in cells_data:
    notebook["cells"].append(create_cell(cell_type, source))

output_path = 'train_eval.ipynb'
with open(output_path, 'w', encoding='utf-8') as f:
    json.dump(notebook, f, indent=1, ensure_ascii=False)

print(f"File {output_path} generated successfully!")
