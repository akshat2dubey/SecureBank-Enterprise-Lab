#!/usr/bin/env python3
"""Build SecureBank completion reports (.docx and print-ready .html) from
the Markdown sources in this directory. Standard library only — no installs.

    python reports/build_reports.py            # rebuild all three formats
    python reports/build_reports.py --check    # verify the .docx parts are valid XML

The Markdown sources (SecureBank-Stage*-Completion-Report.md) are the
version-controlled truth; the generated .docx/.html are derived artifacts.
PDF: open the .html in a browser and Print -> Save as PDF, or convert the
.docx with LibreOffice/Word.
"""

from __future__ import annotations

import html as html_lib
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

REPORTS_DIR = Path(__file__).resolve().parent
INLINE_RE = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


# --------------------------------------------------------------------------
# Markdown -> blocks
# --------------------------------------------------------------------------

def parse_blocks(lines: list[str]) -> list[dict]:
    """Parse our Markdown subset into block dicts."""
    blocks: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line.strip():
            i += 1
            continue
        if line.strip() == "---":
            blocks.append({"type": "hr"})
            i += 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            blocks.append({"type": "heading", "level": len(m.group(1)), "text": m.group(2)})
            i += 1
            continue
        m = re.match(r"^[-*]\s+(.*)$", line)
        if m:
            blocks.append({"type": "bullet", "text": m.group(1)})
            i += 1
            continue
        if line.startswith("```"):
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i].rstrip())
                i += 1
            i += 1  # skip closing fence
            blocks.append({"type": "code", "lines": code})
            continue
        if line.startswith("|"):
            table: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                row = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                # skip separator rows like |---|---|
                if all(re.fullmatch(r":?-{2,}:?", cell) for cell in row):
                    i += 1
                    continue
                table.append(row)
                i += 1
            blocks.append({"type": "table", "rows": table})
            continue
        blocks.append({"type": "para", "text": line})
        i += 1
    return blocks


def inline_runs(text: str):
    """Split text into (kind, content) runs: 'bold' | 'code' | 'plain'."""
    for token in INLINE_RE.split(text):
        if not token:
            continue
        if token.startswith("**") and token.endswith("**"):
            yield ("bold", token[2:-2])
        elif token.startswith("`") and token.endswith("`"):
            yield ("code", token[1:-1])
        else:
            yield ("plain", token)


# --------------------------------------------------------------------------
# DOCX writer (OOXML via zipfile — stdlib only)
# --------------------------------------------------------------------------

STYLES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>
  <w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:outlineLvl w:val="0"/><w:spacing w:before="360" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="1F4E79"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:outlineLvl w:val="1"/><w:spacing w:before="280" w:after="100"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="2E74B5"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:outlineLvl w:val="2"/><w:spacing w:before="200" w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="404040"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="CodeBlock"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="0"/><w:ind w:left="240"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="18"/></w:rPr></w:style>
  <w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="0"/></w:pPr><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="BFBFBF"/><w:left w:val="single" w:sz="4" w:color="BFBFBF"/><w:bottom w:val="single" w:sz="4" w:color="BFBFBF"/><w:right w:val="single" w:sz="4" w:color="BFBFBF"/><w:insideH w:val="single" w:sz="4" w:color="BFBFBF"/><w:insideV w:val="single" w:sz="4" w:color="BFBFBF"/></w:tblBorders></w:tblPr></w:style>
</w:styles>
"""


def _runs_xml(text: str) -> str:
    out = []
    for kind, content in inline_runs(text):
        rpr = ""
        if kind == "bold":
            rpr = "<w:rPr><w:b/></w:rPr>"
        elif kind == "code":
            rpr = ('<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>'
                   '<w:shd w:val="clear" w:fill="F2F2F2"/></w:rPr>')
        out.append(f'<w:r>{rpr}<w:t xml:space="preserve">{escape(content)}</w:t></w:r>')
    return "".join(out)


def _para_xml(text: str, style: str | None = None, shade: str | None = None) -> str:
    ppr = ""
    if style:
        ppr += f'<w:pStyle w:val="{style}"/>'
    if shade:
        ppr += f'<w:shd w:val="clear" w:fill="{shade}"/>'
    return f"<w:p><w:pPr>{ppr}</w:pPr>{_runs_xml(text)}</w:p>"


def _heading_xml(level: int, text: str) -> str:
    return _para_xml(text, style=f"Heading{min(level, 3)}")


def _bullet_xml(text: str) -> str:
    return (
        '<w:p><w:pPr><w:ind w:left="360"/></w:pPr>'
        f'<w:r><w:t xml:space="preserve">\u2022  </w:t></w:r>{_runs_xml(text)}</w:p>'
    )


def _code_xml(lines: list[str]) -> str:
    paras = []
    for line in lines:
        paras.append(
            '<w:p><w:pPr><w:pStyle w:val="CodeBlock"/>'
            '<w:shd w:val="clear" w:fill="F5F5F5"/></w:pPr>'
            f'<w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>'
        )
    return "".join(paras)


def _table_xml(rows: list[list[str]]) -> str:
    body = []
    for r_idx, row in enumerate(rows):
        cells = []
        for cell in row:
            ppr = '<w:pPr><w:spacing w:after="0"/></w:pPr>'
            if r_idx == 0:
                cell_xml = (
                    '<w:tc><w:tcPr>'
                    f'<w:shd w:val="clear" w:fill="DDEBF7"/>'
                    '<w:tcW w:w="0" w:type="auto"/>'
                    f"</w:tcPr><w:p>{ppr}{_runs_xml(cell)}</w:p></w:tc>"
                )
            else:
                cell_xml = (
                    "<w:tc><w:tcPr><w:tcW w:w=\"0\" w:type=\"auto\"/></w:tcPr>"
                    f"<w:p>{ppr}{_runs_xml(cell)}</w:p></w:tc>"
                )
            cells.append(cell_xml)
        body.append(f"<w:tr>{''.join(cells)}</w:tr>")
    return (
        "<w:tbl><w:tblPr><w:tblStyle w:val=\"TableGrid\"/>"
        '<w:tblW w:w="0" w:type="auto"/></w:tblPr>'
        f"{''.join(body)}</w:tbl>"
    )


def docx_body(blocks: list[dict]) -> str:
    parts = []
    for block in blocks:
        if block["type"] == "heading":
            parts.append(_heading_xml(block["level"], block["text"]))
        elif block["type"] == "para":
            parts.append(_para_xml(block["text"]))
        elif block["type"] == "bullet":
            parts.append(_bullet_xml(block["text"]))
        elif block["type"] == "code":
            parts.append(_code_xml(block["lines"]))
        elif block["type"] == "table":
            parts.append(_table_xml(block["rows"]))
        elif block["type"] == "hr":
            parts.append('<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" '
                         'w:space="1" w:color="BFBFBF"/></w:pBdr></w:pPr></w:p>')
    return "".join(parts)


def write_docx(md_path: Path, out_path: Path) -> None:
    blocks = parse_blocks(md_path.read_text(encoding="utf-8").splitlines())
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{docx_body(blocks)}"
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/>'
        "</w:sectPr></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        "</Relationships>"
    )
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/styles.xml", STYLES_XML)
        zf.writestr("word/_rels/document.xml.rels", doc_rels)


# --------------------------------------------------------------------------
# HTML writer (print-ready: open in browser -> Save as PDF)
# --------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  @page {{ size: A4; margin: 18mm; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 11pt; line-height: 1.5; color: #1a1a1a; max-width: 820px; margin: 0 auto; padding: 24px; }}
  h1 {{ color: #1F4E79; font-size: 20pt; border-bottom: 2px solid #1F4E79; padding-bottom: 6px; }}
  h2 {{ color: #2E74B5; font-size: 15pt; margin-top: 26px; border-bottom: 1px solid #c9d6e5; padding-bottom: 3px; }}
  h3 {{ color: #404040; font-size: 12.5pt; margin-top: 20px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 9.5pt; }}
  th {{ background: #DDEBF7; text-align: left; }}
  th, td {{ border: 1px solid #BFBFBF; padding: 5px 8px; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #f7f9fc; }}
  code, pre {{ font-family: Consolas, 'Courier New', monospace; font-size: 9pt; background: #F2F2F2; border-radius: 3px; }}
  code {{ padding: 1px 4px; }}
  pre {{ padding: 10px 12px; border-left: 3px solid #2E74B5; overflow-x: auto; }}
  li {{ margin: 3px 0; }}
  hr {{ border: none; border-top: 1px solid #BFBFBF; margin: 18px 0; }}
  .meta {{ color: #555; font-size: 10pt; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def html_body(blocks: list[dict]) -> str:
    parts = []
    for block in blocks:
        if block["type"] == "heading":
            level = min(block["level"], 3)
            parts.append(f"<h{level}>{html_lib.escape(block['text'])}</h{level}>")
        elif block["type"] == "para":
            parts.append(f"<p>{inline_html(block['text'])}</p>")
        elif block["type"] == "bullet":
            parts.append(f"<li>{inline_html(block['text'])}</li>")
        elif block["type"] == "code":
            parts.append("<pre>" + "".join(
                html_lib.escape(line) + "\n" for line in block["lines"]) + "</pre>")
        elif block["type"] == "table":
            rows = []
            for r_idx, row in enumerate(block["rows"]):
                tag = "th" if r_idx == 0 else "td"
                rows.append("<tr>" + "".join(
                    f"<{tag}>{inline_html(cell)}</{tag}>" for cell in row) + "</tr>")
            parts.append("<table>" + "".join(rows) + "</table>")
        elif block["type"] == "hr":
            parts.append("<hr>")
    return "".join(parts)


def inline_html(text: str) -> str:
    out = []
    for kind, content in inline_runs(text):
        if kind == "bold":
            out.append(f"<strong>{html_lib.escape(content)}</strong>")
        elif kind == "code":
            out.append(f"<code>{html_lib.escape(content)}</code>")
        else:
            out.append(html_lib.escape(content))
    return "".join(out)


def write_html(md_path: Path, out_path: Path) -> None:
    blocks = parse_blocks(md_path.read_text(encoding="utf-8").splitlines())
    title = blocks[0]["text"] if blocks and blocks[0]["type"] == "heading" else md_path.stem
    body = html_body(blocks)
    # Wrap consecutive <li> items in <ul>
    body = re.sub(r"(<li>.*?</li>)(\s*<li>)", r"<ul>\1\2", body, flags=re.S)
    body = re.sub(r"(</li>)(\s*)(?!<li>)", r"\1</ul>", body)
    out_path.write_text(
        HTML_TEMPLATE.format(title=html_lib.escape(title), body=body), encoding="utf-8"
    )


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def check_docx(path: Path) -> bool:
    """Unzip the docx and confirm every XML part parses."""
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith(".xml") or name.endswith(".rels"):
                    ET.fromstring(zf.read(name))
            size = sum(i.file_size for i in zf.infolist() if not i.is_dir())
    except Exception as error:  # noqa: BLE001
        print(f"  INVALID {path.name}: {error}")
        return False
    print(f"  OK {path.name} ({size} bytes, all XML parts valid)")
    return True


def main() -> int:
    md_files = sorted(REPORTS_DIR.glob("SecureBank-Stage*-Completion-Report.md"))
    if not md_files:
        print(f"No report Markdown sources found in {REPORTS_DIR}")
        return 1
    ok = True
    for md in md_files:
        docx = md.with_suffix(".docx")
        html = md.with_suffix(".html")
        print(f"Building {md.name} ...")
        write_docx(md, docx)
        write_html(md, html)
        ok = check_docx(docx) and ok
    if "--check" in sys.argv:
        print("All generated files validated.")
    else:
        print("\nDone. Outputs in reports/:")
        for md in md_files:
            print(f"  {md.with_suffix('.docx').name}  (Microsoft Word)")
            print(f"  {md.with_suffix('.html').name}  (open in browser -> Print -> Save as PDF)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
