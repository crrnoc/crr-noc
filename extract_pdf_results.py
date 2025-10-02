#!/usr/bin/env python3
"""
extract_pdf_results.py

Usage:
  python extract_pdf_results.py --input uploads/result.pdf --semester "1-1"

Outputs JSON to stdout (array of {regno, semester, subcode, subname, grade, sgpa})
"""

import pdfplumber
import re
import json
import argparse

# Regex patterns
code_regex = re.compile(r'\b\d{2}[A-Z]{2}\d{4}[A-Z0-9]*\b')   # e.g. 24BS1003
regno_regex = re.compile(r'^\d{2}[A-Z0-9]{7,}$')              # e.g. 24B81A0101
mapping_regex = re.compile(r'^\s*\d+\)\s*([0-9A-Z]+)\s*-\s*(.+)$')  # e.g. "1) 24BS1003-Communicative English"

def extract_pages_text(pdf_path):
    """Extract text from all pages using pdfplumber"""
    pages_text = []
    with pdfplumber.open(pdf_path) as pdf:
        for p in pdf.pages:
            text = p.extract_text() or ""
            pages_text.append(text)
    return pages_text

def parse_pdf(pdf_path, semester=""):
    pages = extract_pages_text(pdf_path)
    records = []
    subject_map = {}   # subcode → subname

    for page_text in pages:
        lines = [ln.strip() for ln in page_text.splitlines() if ln.strip()]

        # Step 1: Collect mapping lines (can contain multiple mappings in one line)
        for ln in lines:
            # Split a line wherever "1) 24CODE-" etc. starts
            parts = re.split(r'(?=\d+\)\s*[0-9A-Z]+-)', ln)
            for part in parts:
                m = mapping_regex.match(part.strip())
                if m:
                    code, name = m.group(1).strip(), m.group(2).strip()
                    subject_map[code] = name

        current_codes = []
        # Step 2: Parse student rows
        for idx, ln in enumerate(lines):
            # detect subject codes line (contains SGPA and subcodes)
            if "SGPA" in ln:
                found = code_regex.findall(ln)
                if len(found) >= 2:
                    current_codes = found
                continue

            parts = ln.split()
            if len(parts) < 4:
                continue

            # Detect student row
            if parts[0].isdigit() and regno_regex.match(parts[1]):
                regno = parts[1]
                try:
                    sgpa_val = float(parts[-1])
                except:
                    continue
                grades = parts[2:-1]

                # Step 3: Map grades to subject codes
                for i, code in enumerate(current_codes):
                    grade_token = grades[i] if i < len(grades) else ""
                    subname = subject_map.get(code, "")  # ✅ only from mapping dict
                    records.append({
                        "regno": regno,
                        "semester": semester,
                        "subcode": code,
                        "subname": subname,
                        "grade": grade_token,
                        "sgpa": sgpa_val
                    })
    return records

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", required=True, help="input PDF path")
    parser.add_argument("--semester", "-s", default="", help="semester label")
    parser.add_argument("--pretty", action="store_true", help="pretty print JSON")
    args = parser.parse_args()

    recs = parse_pdf(args.input, args.semester)
    if args.pretty:
        print(json.dumps(recs, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(recs, ensure_ascii=False))

if __name__ == "__main__":
    main()
