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

# ✅ Percentage cleaning (only for PDF values)
def clean_percentage(value):
    """Convert float/str percentage into '<value>%' """
    if pd.isna(value):
        return "0%"
    if isinstance(value, str):
        value = value.strip()
        if not value.endswith("%"):
            value += "%"
        return value
    try:
        return f"{round(float(value), 2)}%"
    except:
        return "0%"

# ✅ PDF line parser
def parse_attendance_line(line):
    # regno + subject data + total + present + percentage
    match = re.match(r"^(2[0-9]B81A\d{4})\s+(?:\d+/\d+\s+){6,8}(\d+)/(\d+)\s+([\d.]+)", line)
    if match:
        regno = match.group(1)
        present = int(match.group(2))
        total = int(match.group(3))
        percent = clean_percentage(match.group(4))  # string with %
        return [regno, semester, total, present, percent]
    return None

# ✅ Process PDF
if file_ext == ".pdf":
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
elif file_ext in [".xlsx", ".xls"]:
    try:
        df = pd.read_excel(
            file_path,
            skiprows=5,  # skip headings
            engine="openpyxl" if file_ext == ".xlsx" else "xlrd"
        )

        for _, row in df.iterrows():
            try:
                regno = str(row[1]).strip()       # 2nd column = RegNo
                total = int(row[-3])              # 3rd from last = Total
                present = int(row[-2])            # 2nd from last = Present
                percent = str(row[-1]).strip()    # Last col = Percentage

                # Ensure %
                if percent and not percent.endswith("%"):
                    percent += "%"

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
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['regno', 'semester', 'total_classes', 'attended_classes', 'percentage'])
        writer.writerows(results)
except Exception as e:
    print(json.dumps({"error": f"CSV writing failed: {str(e)}"}))
    sys.exit(1)

# ✅ Return JSON
print(json.dumps(results))
