import os
import re
import fitz  
import requests
from pathlib import Path
from subprocess import run

# Git-repo
REPO_URL = "https://github.com/oak-security/audit-reports"
ZIP_URL = REPO_URL + "/archive/refs/heads/main.zip"
LOCAL_ZIP = "oak_audits.zip"
EXTRACT_DIR = "oak_reports"

# Patterns
CLEAN_PATTERNS = [
    r'.*Security Audit Report.*',
    r'.*Audit Report.*',
    r'Page\s+\d+',
]

HEADER_FOOTER_PATTERNS = [
    r'^Page\s+\d+(\s+of\s+\d+)?$',
    r'^.*Security Audit Report.*$',
    r'^.*Audit Report.*$',
    r'^.*Dusk.*$',
    r'^.*Protocol Review Report.*$',
]

DETAIL_RX = re.compile(r'Detailed\s+(?:\n|\r|\r\n)?\s*Findings', re.IGNORECASE)

FINDING_RX = re.compile(
    r"^\s*(?P<number>\d+)\.?\s*\n?(?P<title>[^\n]+?)\s*\n"
    r".*?Severity:\s*(?P<severity>[^\n]+)\s*\n"
    r"(?P<description>.*?)?"
    r"\bRecommendation\b[:\s]*\n(?P<recommendation>.*?)\n"
    r"Status:\s*(?P<status>[^\n]+)",
    re.IGNORECASE | re.DOTALL | re.MULTILINE
)

FINDING_BLOCK_RX = re.compile(
    r"(?P<number>\d+)\.\s+(?P<title>[^\n]+?)\n+"
    r"(?P<description>.*?)?Recommendation\s*\n(?P<recommendation>.+?)\n+"
    r"Team Response\s*\n(?P<team_response>.+?)(?=\n\d+\.\s|\Z)",
    re.DOTALL | re.IGNORECASE
)

def clean_all_text(text): 
    for pat in CLEAN_PATTERNS:
        text = re.sub(pat + r".*?\n", '', text, flags=re.IGNORECASE)
    text = re.sub(r'[\u200B\u200C\u200D\uFEFF\u202F]', '', text)
    lines = [l for l in text.splitlines() if not re.match(r'^\d+$', l.strip())]
    return '\n'.join(lines)

def clean(text):
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if any(re.match(pat, line, re.IGNORECASE) for pat in HEADER_FOOTER_PATTERNS):
            continue
        if re.fullmatch(r'\d+', line):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)

def download_and_extract_repo():
    if not os.path.exists(LOCAL_ZIP):
        print("[*] Downloading audit reports zip...")
        response = requests.get(ZIP_URL)
        with open(LOCAL_ZIP, 'wb') as f:
            f.write(response.content)
    else:
        print("[*] Zip already downloaded.")
    if not os.path.exists(EXTRACT_DIR):
        print("[*] Extracting zip...")
        run(["unzip", "-q", LOCAL_ZIP, "-d", "."])
        os.rename("audit-reports-main", EXTRACT_DIR)
    else:
        print("[*] Extract directory already exists.")

def extract_links_from_pdf(doc):
    all_links = []
    for page_num, page in enumerate(doc):
        words = page.get_text("words")
        links = page.get_links()
        for link in links:
            if 'uri' in link:
                rect = fitz.Rect(link['from'])
                anchor_text = " ".join(
                    w[4] for w in words if fitz.Rect(w[:4]).intersects(rect)
                ).strip()
                all_links.append({
                    "page": page_num,
                    "url": link['uri'],
                    "anchor_text": anchor_text,
                })
    return all_links

def match_links_to_patch_entries(findings, pdf_links, text_key="recommendation"):
    for f in findings:
        combined_text = f.get(text_key, "") + " " + f.get("description", "")
        hashes = re.findall(r'\b[a-f0-9]{7,40}\b', combined_text)
        matched_links = []
        for link in pdf_links:
            if link['anchor_text'] and link['anchor_text'] in combined_text:
                matched_links.append(link['url'])
            elif any(h in link['anchor_text'] for h in hashes):
                matched_links.append(link['url'])
            elif link['url'] in combined_text:
                matched_links.append(link['url'])
        f['patch_links'] = list(dict.fromkeys(matched_links))
    return findings

def extract_codebase_info_per_commit(pdf_path):
    doc = fitz.open(pdf_path)
    all_lines = []
    for page in doc:
        lines = page.get_text().splitlines()
        all_lines.extend(lines)
    doc.close()
    entries = []
    current_repo = None
    for i, line in enumerate(all_lines):
        gh_match = re.search(r"https://github\.com/[^\s\)]+", line)
        if gh_match:
            current_repo = gh_match.group(0)
        if re.search(r"\bcommits?\b", line.lower()) and current_repo:
            for j in range(i, min(i + 3, len(all_lines))):
                hashes = re.findall(r'\b[a-f0-9]{7,40}\b', all_lines[j])
                for h in hashes:
                    entries.append((current_repo, h))
    return entries

def extract_findings_from_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    full_text = "\n".join(clean_all_text(page.get_text()) for page in doc)
    links = extract_links_from_pdf(doc)
    doc.close()

    dusk_matches = list(FINDING_BLOCK_RX.finditer(full_text))
    if dusk_matches:
        findings = []
        for match in dusk_matches:
            findings.append({
                'number': match.group('number').strip(),
                'title': " ".join(match.group('title').splitlines()).strip(),
                'description': " ".join(match.group('description').splitlines()).strip(),
                'recommendation': " ".join(match.group('recommendation').splitlines()).strip(),
                'team_response': " ".join(match.group('team_response').splitlines()).strip(),
            })
        findings = match_links_to_patch_entries(findings, links, "team_response")
        return findings, True

    pages = [clean_all_text(page.get_text()) for page in fitz.open(pdf_path)]
    full_text = '\n'.join(pages)
    m = DETAIL_RX.search(full_text)
    if not m:
        return [], False
    section = full_text[m.end():]
    section = re.split(r"^\d+\.\s+Appendix", section, flags=re.MULTILINE | re.IGNORECASE)[0]

    findings = []
    for match in FINDING_RX.finditer(section):
        desc = " ".join(line.strip() for line in match.group('description').splitlines())
        rec = " ".join(line.strip() for line in match.group('recommendation').splitlines())
        findings.append({
            'number': match.group('number').strip(),
            'title': match.group('title').strip(),
            'severity': match.group('severity').strip(),
            'description': desc.strip(),
            'recommendation': rec.strip(),
            'status': match.group('status').strip(),
        })
    findings = match_links_to_patch_entries(findings, links)
    return findings, True

def save_findings_to_txt(pdf_path, codebase_entries, findings):
    out_path = os.path.splitext(pdf_path)[0] + '_findings.txt'
    with open(out_path, 'w', encoding='utf-8') as f:
        for idx, (repo, commit) in enumerate(codebase_entries, 1):
            f.write(f"{idx}.\nRepository: {repo}\nCommit: {commit}\n")
            f.write("#################################################################\n")
        if codebase_entries:
            f.write("====\n")
        for fn in findings:
            f.write(f"Finding #{fn['number']}\n")
            f.write(f"Title: {fn['title']}\n")
            f.write(f"Description: {fn['description']}\n")
            f.write(f"Recommendation: {fn['recommendation']}\n")
            if 'team_response' in fn:
                f.write(f"Team Response: {fn['team_response']}\n")
            if 'severity' in fn:
                f.write(f"Severity: {fn['severity']}\n")
            if 'status' in fn:
                f.write(f"Status: {fn['status']}\n")
            for link in fn.get("patch_links", []):
                f.write(f"Link: {link}\n")
            f.write("================================================================\n")
    return out_path

def process_all_pdfs():
    download_and_extract_repo()
    root = Path(EXTRACT_DIR)
    pdf_paths = list(root.rglob("*.pdf"))
    extracted_count = 0
    total_findings = 0

    for pdf in pdf_paths:
        findings, success = extract_findings_from_pdf(str(pdf))
        if not success:
            continue
        codebase = extract_codebase_info_per_commit(str(pdf))
        save_findings_to_txt(str(pdf), codebase, findings)
        extracted_count += 1
        total_findings += len(findings)

    print(f"Total PDFs found: {len(pdf_paths)}")
    print(f"Successfully extracted: {extracted_count}")
    print(f"Total findings extracted: {total_findings}")

process_all_pdfs()
