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
file_ext = sys.argv[3].lower()
results = []

# ✅ Output CSV path
csv_name = os.path.splitext(os.path.basename(file_path))[0] + ".csv"
csv_path = os.path.join("uploads", csv_name)

# ✅ Percentage cleaning function
def clean_percentage(value):
    """Clean percentage values like '73.20%' or 73.20 into float"""
    if pd.isna(value):
        return 0.0
    if isinstance(value, str):
        value = value.strip().replace("%", "")
    try:
        return round(float(value), 2)
    except:
        return 0.0

# ✅ Regex for PDF parsing
def parse_attendance_line(line):
    # Matches regno + attendance values + total + attended + percentage
    match = re.match(r"^(2[0-9]B81A\d{4})\s+(?:\d+/\d+\s+){6,8}(\d+)/(\d+)\s+([\d.]+)", line)
    if match:
        regno = match.group(1)
        present = int(match.group(2))
        total = int(match.group(3))
        percent = clean_percentage(match.group(4))
        return [regno, semester, total, present, percent]
    return None

# ✅ Process PDF files
if file_ext == ".pdf":
    try:
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if not text:
                    continue
                lines = text.split("\n")
                for line in lines:
                    parsed = parse_attendance_line(line.strip())
                    if parsed:
                        results.append(parsed)
    except Exception as e:
        print(json.dumps({"error": f"PDF parsing failed: {str(e)}"}))
        sys.exit(1)

# ✅ Process Excel files
elif file_ext in [".xlsx", ".xls"]:
    try:
        # Read Excel dynamically (skip first 5 rows → heading section)
        df = pd.read_excel(
            file_path,
            skiprows=5,
            engine="openpyxl" if file_ext == ".xlsx" else "xlrd"
        )

        # Expected structure: SNo | RegNo | ... | Total | Attended | %
        for _, row in df.iterrows():
            try:
                regno = str(row[1]).strip()  # 2nd column = RegNo
                total = row[-3]              # 3rd column from last = Total
                present = row[-2]            # 2nd column from last = Attended
                percent = clean_percentage(row[-1])  # Last column = Percentage

                # Validate RegNo → must start with 2 & length 10
                if regno and regno.startswith("2") and len(regno) == 10:
                    results.append([regno, semester, int(total), int(present), percent])
            except:
                continue
    except Exception as e:
        print(json.dumps({"error": f"Excel parsing failed: {str(e)}"}))
        sys.exit(1)

# ❌ Unsupported format
else:
    print(json.dumps({"error": "Unsupported file format. Please upload PDF or Excel only."}))
    sys.exit(1)

# ✅ Save to CSV
try:
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['regno', 'semester', 'total_classes', 'attended_classes', 'percentage'])
        writer.writerows(results)
except Exception as e:
    print(json.dumps({"error": f"CSV writing failed: {str(e)}"}))
    sys.exit(1)

# ✅ Return JSON output to Node.js
print(json.dumps(results))
