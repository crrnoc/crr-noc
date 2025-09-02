import sys
import os
import pdfplumber
import json
import re
import openpyxl

if len(sys.argv) < 3:
    print("Usage: extract_attendance.py <pdf_path> <semester>")
    sys.exit(1)

pdf_path = sys.argv[1]
semester = sys.argv[2]
results = []

excel_name = os.path.splitext(os.path.basename(pdf_path))[0] + ".xlsx"
excel_path = os.path.join("uploads", excel_name)

def parse_attendance_line(line):
    # Match regno like 23B81A4501 followed by groups of attendance like 12/14 28/35 ... then total like 110/133 and percent
    match = re.match(r"^(2[0-9]B81A\d{4})\s+(?:\d+/\d+\s+){6,8}(\d+)/(\d+)\s+([\d.]+)", line)
    if match:
        regno = match.group(1)
        present = int(match.group(2))
        total = int(match.group(3))
        percent = float(match.group(4))
        return [regno, semester, total, present, percent]
    return None

with pdfplumber.open(pdf_path) as pdf:
    for page in pdf.pages:
        text = page.extract_text()
        if not text:
            continue
        lines = text.split("\n")
        for line in lines:
            parsed = parse_attendance_line(line.strip())
            if parsed:
                results.append(parsed)

# ✅ Save to Excel
workbook = openpyxl.Workbook()
sheet = workbook.active
sheet.title = "Attendance"

# Header row
headers = ['Reg No', 'Semester', 'Total Classes', 'Attended Classes', 'Percentage']
sheet.append(headers)

# Data rows
for row in results:
    sheet.append(row)

# Auto-fit columns
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

# ✅ Output JSON for Node.js
print(json.dumps(results))
