import sys
import os
import pdfplumber
import json
import re
import pandas as pd
import openpyxl

# -------------------- Arguments Validation --------------------
if len(sys.argv) < 4:
    print("Usage: extract_attendance.py <file_path> <semester> <extension>")
    sys.exit(1)

file_path = sys.argv[1]
semester = sys.argv[2]
file_ext = sys.argv[3].lower()
results = []

# Final cleaned Excel path
excel_name = os.path.splitext(os.path.basename(file_path))[0] + ".xlsx"
excel_path = os.path.join("uploads", excel_name)


# -------------------- Attendance Line Parser (PDF) --------------------
def parse_attendance_line(line):
    """
    Expected pattern:
    23B81A4501  5/6  8/9  10/11 ... 110/120 85.71
    """
    match = re.match(r"^(2[0-9]B81A\d{4})\s+(?:\d+/\d+\s+){6,10}(\d+)/(\d+)\s+([\d.]+)", line)
    if match:
        regno = match.group(1)
        present = int(match.group(2))
        total = int(match.group(3))
        percent = float(match.group(4))
        return [regno, semester, total, present, percent]
    return None


# -------------------- Process PDF --------------------
if file_ext == ".pdf":
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


# -------------------- Process Excel (.xlsx / .xls) --------------------
elif file_ext in [".xlsx", ".xls"]:
    try:
        # Read Excel using pandas → handles .xls & .xlsx both
        df = pd.read_excel(file_path, engine="openpyxl" if file_ext == ".xlsx" else "xlrd")

        # Expected Columns: RegNo | CH | CA | %
        # Auto-detect column names dynamically
        df.columns = [str(col).strip().lower() for col in df.columns]

        # Possible header variations
        reg_col = next((c for c in df.columns if "reg" in c or "roll" in c), df.columns[0])
        total_col = next((c for c in df.columns if c in ["ch", "total", "classes", "total_classes"]), df.columns[1])
        present_col = next((c for c in df.columns if c in ["ca", "attended", "present", "classes_attended"]), df.columns[2])
        percent_col = next((c for c in df.columns if "%" in c or "percent" in c), df.columns[3])

        for _, row in df.iterrows():
            regno = str(row[reg_col]).strip()
            total = int(row[total_col]) if not pd.isna(row[total_col]) else 0
            present = int(row[present_col]) if not pd.isna(row[present_col]) else 0

            percent_val = str(row[percent_col]).replace("%", "").strip()
            percent = float(percent_val) if percent_val else 0.0

            if regno and regno.lower() != "nan":
                results.append([regno, semester, total, present, percent])

    except Exception as e:
        print(json.dumps({"error": f"Excel parsing failed: {str(e)}"}))
        sys.exit(1)


# -------------------- Unsupported File Type --------------------
else:
    print(json.dumps({"error": "Unsupported file format. Please upload PDF or Excel only."}))
    sys.exit(1)


# -------------------- Save Cleaned Excel --------------------
workbook = openpyxl.Workbook()
sheet = workbook.active
sheet.title = "Attendance"

headers = ["Reg No", "Semester", "Total Classes", "Attended Classes", "Percentage"]
sheet.append(headers)

for row in results:
    sheet.append(row)

# Auto-adjust column widths
for column in sheet.columns:
    max_length = 0
    col = column[0].column_letter
    for cell in column:
        try:
            if len(str(cell.value)) > max_length:
                max_length = len(str(cell.value))
        except:
            pass
    sheet.column_dimensions[col].width = max_length + 2

workbook.save(excel_path)

# -------------------- Output Final JSON --------------------
print(json.dumps(results))
