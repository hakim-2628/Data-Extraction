!pip install PyMuPDF
import requests
import os
import re
import fitz
from pathlib import Path
import base64

def clean_text(text):
    text = re.sub(r'[\s\u200b\u200c\u200d\u202f\u00a0\u1680\u180e\u2000-\u200a\u2028\u2029\u205f\u3000]+', ' ', text)
    text = re.sub(r'^\s*\d+\s*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'©\s*20\d{2}\s+Informal Systems', '', text, flags=re.IGNORECASE)
    text = re.sub(r'^[-=]{4,}$', '', text, flags=re.MULTILINE)
    text = re.sub(r'\n{2,}', '\n', text)
    return text.strip()

def remove_header_footer_and_page_numbers(page, header_y_range=(0, 70), footer_y_threshold=750, page_num_min_y=400):
    blocks = page.get_text("dict")["blocks"]
    blocks_to_remove = []
    individual_lines_to_remove = []
    manual_header_keywords = []

    for block in blocks:
        if "lines" not in block:
            continue
        y0 = block["bbox"][1]
        block_lines = [
            "".join(span["text"].strip() for span in line["spans"]).strip()
            for line in block["lines"]
        ]
        block_text = "\n".join(block_lines)
        if header_y_range[0] <= y0 <= header_y_range[1]:
            blocks_to_remove.append(block_text)
            continue
        if y0 >= footer_y_threshold:
            if ():
                blocks_to_remove.append(block_text)
                continue
        if y0 >= page_num_min_y:
            for line in block_lines:
                if line.strip().isdigit() and len(line.strip()) <= 3:
                    individual_lines_to_remove.append(line.strip())
    full_text = page.get_text()
    for block in blocks_to_remove:
        full_text = full_text.replace(block, "")
    for line in individual_lines_to_remove:
        full_text = re.sub(rf'^\s*{re.escape(line)}\s*$', '', full_text, flags=re.MULTILINE)
    for pattern in manual_header_keywords:
        full_text = re.sub(pattern, '', full_text, flags=re.IGNORECASE)
    return full_text.strip()




def get_findings_start_page(pdf_path):
    doc = fitz.open(pdf_path)
    findings_page = None

    for page_index in range(1, min(len(doc), 5)):
        page = doc[page_index]
        text = page.get_text()

        match = re.search(r'(Technical\s+Findings|Findings)\s*\.{0,}\s*(\d+)', text, re.IGNORECASE)
        if match:
            findings_label = match.group(1)
            findings_page = int(match.group(2))

            footer_lines = text.splitlines()
            has_footer = any(line.strip() == str(page_index + 1) for line in footer_lines)

            start_page = findings_page if has_footer else findings_page + 4
            break
    else:
        start_page = 0

    field_keywords = [r'Finding ID:', r'Severity:', r'Status:', r'Description', r'Recommendation']
    for i in range(start_page, len(doc)):
        page_text = doc[i].get_text()
        matches = sum(1 for pattern in field_keywords if re.search(pattern, page_text, re.IGNORECASE))
        if matches >= 2:
            return i
    return 0





def extract_findings_section_from_pdf(pdf_path, start_page=0):
    doc = fitz.open(pdf_path)
    text = ""
    for i in range(start_page, len(doc)):
        cleaned = remove_header_footer_and_page_numbers(doc[i])
        text += cleaned + "\n\f"
    return text

def extract_structured_findings_from_raw(text):
    findings = []
    pattern = re.compile(r'Finding ID:\s*([A-Z0-9\-]+)', re.IGNORECASE)
    matches = list(pattern.finditer(text))
    
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end].strip()
        context_before = text[:start].strip().splitlines()
        title = "N/A"
        if context_before:
            last_line = context_before[-1].strip()
            if last_line and not last_line.lower().startswith(("finding", "title", "severity", "status")):
                title = last_line

        entry = {
            "number": str(i + 1),
            "title": title,
            "id": "N/A",
            "severity": "N/A",
            "status": "N/A",
            "description": "N/A",
            "recommendation": "N/A",
            "severity_impact_summary": "N/A",
            "filename": "N/A",
            "line": "N/A"
        }
        id_match = re.search(r'Finding ID:\s*([A-Z0-9\-]+)', block, flags=re.IGNORECASE)
        severity_match = re.search(r'Severity:\s*(\w+)', block, flags=re.IGNORECASE)
        status_match = re.search(r'Status:\s*(\w+)', block, flags=re.IGNORECASE)
        filename_match = re.search(r'File name:\s*(.+)', block, flags=re.IGNORECASE)
        line_match = re.search(r'Line number:\s*(\d+)', block, flags=re.IGNORECASE)
        description_match = re.search(r'Description\s+(.*?)\s+Proof of Issue', block, flags=re.DOTALL | re.IGNORECASE)
        recommendation_match = re.search(r'Recommendation\s+(.*?)\s*(Severity and Impact Summary|Filename|Line Number|$)', block, flags=re.DOTALL | re.IGNORECASE)
        severity_impact_match = re.search(r'Severity and Impact Summary\s+(.*?)\s*(Filename|Line Number|$)', block, flags=re.DOTALL | re.IGNORECASE)

        if id_match:
            entry["id"] = id_match.group(1).strip()
        if severity_match:
            entry["severity"] = severity_match.group(1).strip()
        if status_match:
            entry["status"] = status_match.group(1).strip()
        if description_match:
            desc = description_match.group(1).replace('\n', ' ')
            desc = re.sub(r'\s+', ' ', desc).strip()
            entry["description"] = desc
        if recommendation_match:
            rec = recommendation_match.group(1).replace('\n', ' ')
            rec = re.sub(r'\s+', ' ', rec).strip()
            entry["recommendation"] = rec
        if filename_match:
            entry["filename"] = filename_match.group(1).strip()
        if line_match:
            entry["line"] = line_match.group(1).strip()
        if severity_impact_match:
            si_summary = severity_impact_match.group(1).replace('\n', ' ')
            si_summary = re.sub(r'\s+', ' ', si_summary).strip()
            entry["severity_impact_summary"] = si_summary
        findings.append(entry)

    return findings


def write_structured_findings_txt(output_path, findings):
    with open(output_path, 'w', encoding='utf-8') as f:
        for item in findings:
            f.write(f"Finding #{item['number']}\n")
            f.write(f"Title: {item['title']}\n")
            f.write(f"ID: {item['id']}\n")
            f.write(f"Severity: {item['severity']}\n")
            f.write(f"Status: {item['status']}\n")
            f.write(f"Description:\n{item['description']}\n")
            f.write(f"Severity and Impact Summary:\n{item['severity_impact_summary']}\n")
            f.write(f"Filename: {item['filename']}\n")
            f.write(f"Line Number: {item['line']}\n")
            f.write(f"Recommendation:\n{item['recommendation']}\n")
            f.write("=" * 72 + "\n")


def download_pdfs_from_github_api(repo, path, local_dir):
    api_url = f"https://api.github.com/repos/{repo}/contents/{path}"
    response = requests.get(api_url)
    if response.status_code != 200:
        print(f"Failed to fetch contents of {path}: {response.status_code}")
        return

    for item in response.json():
        item_path = item['path']
        item_type = item['type']
        if item_type == "file" and item_path.lower().endswith(".pdf"):
            download_url = item['download_url']
            local_path = os.path.join(local_dir, item_path.replace("Code Audit Reports/", ""))
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            print(f"Downloading {item_path}...")
            pdf_response = requests.get(download_url)
            if pdf_response.status_code == 200:
                with open(local_path, "wb") as f:
                    f.write(pdf_response.content)
                print(f"Saved: {local_path}")
            else:
                print(f"Failed to download {item_path}")
        elif item_type == "dir":
            download_pdfs_from_github_api(repo, item_path, local_dir)

if __name__ == "__main__":
    repo = "fyeo-io/public-audit-reports"
    root_path = "Code Audit Reports"
    local_dir = "fyeo_reports"
    download_pdfs_from_github_api(repo, root_path, local_dir)

    for root, _, files in os.walk(local_dir):
        for file in files:
            if file.endswith(".pdf"):
                input_path = os.path.join(root, file)
                try:
                    start_page = get_findings_start_page(input_path)
                    raw_text = extract_findings_section_from_pdf(input_path, start_page)
                    findings = extract_structured_findings_from_raw(raw_text)
                    txt_output = Path(input_path).with_name(Path(input_path).stem + "_structured_findings.txt")
                    write_structured_findings_txt(txt_output, findings)
                    print(f"Extracted: {file}")
                except Exception:
                    pass