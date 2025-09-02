import sys
import os
import pdfplumber
import csv
import json
import re
import pandas as pd

if len(sys.argv) < 4:
    print("Usage: extract_attendance.py <file_path> <semester> <extension>")
    sys.exit(1)

file_path = sys.argv[1]
semester = sys.argv[2]
file_ext = sys.argv[3].lower().replace(".", "")  # normalize like pdf/xlsx
results = []

# ✅ Output CSV path
csv_name = os.path.splitext(os.path.basename(file_path))[0] + ".csv"
csv_path = os.path.join("uploads", csv_name)

# ✅ Convert fractional percentages to human-readable form
def format_percentage(value):
    """Convert fraction to readable percentage, e.g., 0.564 → 56.4%"""
    if value is None or pd.isna(value):
        return "0%"
    try:
        val = float(value)
        if val <= 1:  # fraction
            val = val * 100
        return f"{round(val, 2)}%"
    except:
        # If string with %, just return it
        val = str(value).strip()
        if not val.endswith("%"):
            val += "%"
        return val

# ✅ PDF line parser
def parse_attendance_line(line):
    # regno + subject data + total + present + percentage
    match = re.match(r"^(2[0-9]B81A\d{4})\s+(?:\d+/\d+\s+){6,8}(\d+)/(\d+)\s+([\d.]+)", line)
    if match:
        regno = match.group(1)
        present = int(match.group(2))
        total = int(match.group(3))
        percent = format_percentage(match.group(4))
        return [regno, semester, total, present, percent]
    return None

# ✅ Process PDF
if file_ext == "pdf":
    try:
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if not text:
                    continue
                for line in text.split("\n"):
                    parsed = parse_attendance_line(line.strip())
                    if parsed:
                        results.append(parsed)
    except Exception as e:
        print(json.dumps({"error": f"PDF parsing failed: {str(e)}"}))
        sys.exit(1)

# ✅ Process Excel
elif file_ext in ["xlsx", "xls"]:
    try:
        df = pd.read_excel(
            file_path,
            skiprows=5,  # skip headings
            engine="openpyxl" if file_ext == "xlsx" else "xlrd"
        )

        for _, row in df.iterrows():
            try:
                regno = str(row[1]).strip()       # 2nd column = RegNo
                total = int(row[-3])              # 3rd from last = Total
                present = int(row[-2])            # 2nd from last = Present
                percent = format_percentage(row[-1])  # Last col = Percentage

                if regno and regno.startswith("2") and len(regno) == 10:
                    results.append([regno, semester, total, present, percent])
            except:
                continue
    except Exception as e:
        print(json.dumps({"error": f"Excel parsing failed: {str(e)}"}))
        sys.exit(1)

# ❌ Unsupported
else:
    print(json.dumps({"error": "Unsupported file format. Please upload PDF or Excel only."}))
    sys.exit(1)

# ✅ Save CSV
try:
    os.makedirs("uploads", exist_ok=True)
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['regno', 'semester', 'total_classes', 'attended_classes', 'percentage'])
        writer.writerows(results)
except Exception as e:
    print(json.dumps({"error": f"CSV writing failed: {str(e)}"}))
    sys.exit(1)

# ✅ Return JSON
print(json.dumps(results))
