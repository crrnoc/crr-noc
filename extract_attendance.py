import sys
import os
import pdfplumber
import json
import re
import openpyxl

if len(sys.argv) < 4:
    print("Usage: extract_attendance.py <file_path> <semester> <extension>")
    sys.exit(1)

file_path = sys.argv[1]
semester = sys.argv[2]
file_ext = sys.argv[3].lower()
results = []

excel_name = os.path.splitext(os.path.basename(file_path))[0] + ".xlsx"
excel_path = os.path.join("uploads", excel_name)

def parse_attendance_line(line):
    # For PDF: Match regno like 23B81A4501 followed by CH/CA/% style
    match = re.match(r"^(2[0-9]B81A\d{4})\s+(?:\d+/\d+\s+){6,8}(\d+)/(\d+)\s+([\d.]+)", line)
    if match:
        regno = match.group(1)
        present = int(match.group(2))
        total = int(match.group(3))
        percent = float(match.group(4))
        return [regno, semester, total, present, percent]
    return None

# ✅ Process based on file type
if file_ext == ".pdf":
    # Extract from PDF using pdfplumber
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

elif file_ext in [".xlsx", ".xls"]:
    # Extract from Excel directly
    wb = openpyxl.load_workbook(file_path)
    sheet = wb.active

    # Detect header row first by finding where "Reg No" or "%” exists
    header_row = None
    for idx, row in enumerate(sheet.iter_rows(values_only=True), start=1):
        if row and any(str(cell).strip().lower() in ["regno", "reg no", "register no", "%"] for cell in row):
            header_row = idx
            break

    if not header_row:
        print(json.dumps({"error": "Header row not found in Excel file"}))
        sys.exit(1)

    # Start reading from the row after the header
    for row in sheet.iter_rows(min_row=header_row + 1, values_only=True):
        regno = row[0]
        ch = row[1]   # total classes
        ca = row[2]   # attended classes
        percent = row[3]  # percentage

        # Validate regno properly like 23B81Axxxx
        if regno and re.match(r"^2[0-9]B81A\d{4}$", str(regno).strip()):
            try:
                total = int(ch)
                present = int(ca)
                perc = float(str(percent).replace("%", ""))  # remove % if present
                results.append([str(regno).strip(), semester, total, present, perc])
            except:
                continue

else:
    print(json.dumps({"error": "Unsupported file format. Please upload PDF or Excel only."}))
    sys.exit(1)

# ✅ Save cleaned Excel file
workbook = openpyxl.Workbook()
sheet = workbook.active
sheet.title = "Attendance"

headers = ["Reg No", "Semester", "Total Classes", "Attended Classes", "Percentage"]
sheet.append(headers)

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

# ✅ Output JSON to Node.js
print(json.dumps(results))
