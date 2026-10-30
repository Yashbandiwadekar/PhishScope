"""Small python-docx helpers for the report: styles, captions with SEQ fields, tables, code blocks, page numbers, TOC fields."""
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Inches, Pt, RGBColor

FONT = "Times New Roman"


def set_font(run, size=12, bold=None, italic=None, name=FONT, color=None):
    run.font.name = name
    run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    rpr = run._element.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts")
        rpr.append(rf)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rf.set(qn(a), name)
    if color:
        run.font.color.rgb = RGBColor.from_string(color)


def new_document():
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin, sec.right_margin, sec.top_margin, sec.bottom_margin = Cm(3.2), Cm(2.5), Cm(2.5), Cm(2.5)
    st = doc.styles
    n = st["Normal"]
    n.font.name = FONT
    n.font.size = Pt(12)
    n.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    n.paragraph_format.line_spacing = 1.5
    n.paragraph_format.space_after = Pt(6)
    n.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    for name, size, before, after in (("Heading 1", 15, 0, 14), ("Heading 2", 13, 14, 6), ("Heading 3", 12, 10, 4)):
        h = st[name]
        h.font.name = FONT
        h.font.size = Pt(size)
        h.font.bold = True
        h.font.italic = name == "Heading 3"
        h.font.color.rgb = RGBColor(0, 0, 0)
        rf = h.element.rPr.rFonts
        for att in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
            if rf.get(qn(att)) is not None:
                del rf.attrib[qn(att)]
        for att in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
            rf.set(qn(att), FONT)
        h.paragraph_format.space_before = Pt(before)
        h.paragraph_format.space_after = Pt(after)
        h.paragraph_format.keep_with_next = True
        h.paragraph_format.line_spacing = 1.15
        h.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    cap = st["Caption"]
    cap.font.name = FONT
    cap.font.size = Pt(10.5)
    cap.font.bold = True
    cap.font.italic = False
    cap.font.color.rgb = RGBColor(0, 0, 0)
    cap.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap.paragraph_format.space_after = Pt(10)
    cap.paragraph_format.line_spacing = 1.15
    return doc


def para(doc, text="", size=12, bold=False, italic=False, align=None, space_after=None, keep_next=False, line=None, indent=None):
    p = doc.add_paragraph()
    if align is not None:
        p.alignment = align
    if space_after is not None:
        p.paragraph_format.space_after = Pt(space_after)
    if line is not None:
        p.paragraph_format.line_spacing = line
    if indent is not None:
        p.paragraph_format.left_indent = Cm(indent)
    p.paragraph_format.keep_with_next = keep_next
    add_runs(p, text, size, bold, italic)
    return p


def add_runs(p, text, size=12, bold=False, italic=False):
    """text may contain [[placeholder]] (yellow highlight) and **bold** segments"""
    import re
    for part in re.split(r"(\[\[.*?\]\]|\*\*.*?\*\*)", text):
        if not part:
            continue
        if part.startswith("[["):
            r = p.add_run("[" + part[2:-2] + "]")
            set_font(r, size, bold, italic)
            r.font.highlight_color = 7      # yellow
        elif part.startswith("**"):
            r = p.add_run(part[2:-2])
            set_font(r, size, True, italic)
        else:
            r = p.add_run(part)
            set_font(r, size, bold, italic)


def bullet(doc, text, size=12, level=0):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Cm(1.0 + 0.6 * level)
    p.paragraph_format.first_line_indent = Cm(-0.5)
    p.paragraph_format.space_after = Pt(3)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    add_runs(p, text, size)
    return p


def numbered(doc, text, n, size=12):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(1.0)
    p.paragraph_format.first_line_indent = Cm(-0.7)
    p.paragraph_format.space_after = Pt(3)
    add_runs(p, f"{n}.  " + text, size)
    return p


def heading(doc, text, level=1):
    return doc.add_heading(text, level=level)


def page_break(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def _field(run_parent, instr, cached="1"):
    def mk(kind):
        r = OxmlElement("w:r")
        c = OxmlElement("w:fldChar")
        c.set(qn("w:fldCharType"), kind)
        r.append(c)
        return r
    run_parent.append(mk("begin"))
    r = OxmlElement("w:r")
    it = OxmlElement("w:instrText")
    it.set(qn("xml:space"), "preserve")
    it.text = f" {instr} "
    r.append(it)
    run_parent.append(r)
    run_parent.append(mk("separate"))
    r = OxmlElement("w:r")
    t = OxmlElement("w:t")
    t.text = cached
    r.append(t)
    run_parent.append(r)
    run_parent.append(mk("end"))


class Counter:
    fig = 0
    tab = 0


def caption(doc, kind, text):
    """kind: 'Figure' or 'Table' - numbering continues across the report (Word list-of-figures compatible SEQ fields)."""
    if kind == "Figure":
        Counter.fig += 1
        n = Counter.fig
    else:
        Counter.tab += 1
        n = Counter.tab
    p = doc.add_paragraph(style="Caption")
    r = p.add_run(f"{kind} ")
    set_font(r, 10.5, True)
    _field(p._p, f"SEQ {kind} \\* ARABIC", str(n))
    r2 = p.add_run(f": {text}")
    set_font(r2, 10.5, True)
    p.paragraph_format.keep_with_next = kind == "Table"
    return p


def picture(doc, path, width_cm=14.5, cap=None):
    path = Path(path)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.0
    if path.exists():
        p.add_run().add_picture(str(path), width=Cm(width_cm))
    else:
        r = p.add_run(f"[figure missing: {path.name}]")
        set_font(r, 10, italic=True)
    if cap:
        caption(doc, "Figure", cap)


def shade(cell, fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcPr.append(shd)


def table(doc, headers, rows, widths_cm=None, size=9.5, caption_text=None, align_right_from=None):
    if caption_text:
        caption(doc, "Table", caption_text)
    t = doc.add_table(rows=1 + len(rows), cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for ci, h in enumerate(headers):
        c = t.rows[0].cells[ci]
        c.text = ""
        p = c.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.line_spacing = 1.0
        p.paragraph_format.space_after = Pt(0)
        set_font(p.add_run(str(h)), size, True)
        shade(c, "D9DEE6")
    for ri, row in enumerate(rows, 1):
        for ci, v in enumerate(row):
            c = t.rows[ri].cells[ci]
            c.text = ""
            p = c.paragraphs[0]
            p.paragraph_format.line_spacing = 1.0
            p.paragraph_format.space_after = Pt(0)
            p.alignment = WD_ALIGN_PARAGRAPH.RIGHT if (align_right_from is not None and ci >= align_right_from) else WD_ALIGN_PARAGRAPH.LEFT
            set_font(p.add_run(str(v)), size)
    hdr = t.rows[0]._tr.get_or_add_trPr()
    th = OxmlElement("w:tblHeader")
    hdr.append(th)
    for row in t.rows:
        trPr = row._tr.get_or_add_trPr()
        trPr.append(OxmlElement("w:cantSplit"))
    if widths_cm:
        if sum(widths_cm) > 15.2:                                   # never wider than the text block
            widths_cm = [w * 15.2 / sum(widths_cm) for w in widths_cm]
        t.autofit = False
        for row in t.rows:
            for ci, w in enumerate(widths_cm):
                row.cells[ci].width = Cm(w)
        for gc, w in zip(t._tbl.tblGrid.findall(qn("w:gridCol")), widths_cm):   # Word lays out from the grid, not only the cell widths
            gc.set(qn("w:w"), str(int(Cm(w).twips)))
        tblPr = t._tbl.tblPr
        lay = OxmlElement("w:tblLayout")
        lay.set(qn("w:type"), "fixed")
        tblPr.append(lay)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return t


def code_block(doc, code, size=8.5):
    for line in code.strip("\n").split("\n"):
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.6)
        p.paragraph_format.line_spacing = 1.0
        p.paragraph_format.space_after = Pt(0)
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        r = p.add_run(line if line else " ")
        set_font(r, size, name="Consolas")
        pPr = p._p.get_or_add_pPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), "F2F4F7")
        pPr.append(shd)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def toc_field(doc, instr, placeholder):
    p = doc.add_paragraph()
    p.paragraph_format.line_spacing = 1.15
    _field(p._p, instr, placeholder)
    return p


def section_break(doc, number_format=None, start=None, footer_numbers=True):
    sec = doc.add_section(WD_SECTION.NEW_PAGE)
    sec.footer.is_linked_to_previous = False
    for ch in list(sec.footer._element):
        sec.footer._element.remove(ch)
    sec.footer._element.append(OxmlElement("w:p"))
    if footer_numbers:
        p = sec.footer.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _field(p._p, "PAGE", "1")
    pg = sec._sectPr.find(qn("w:pgNumType"))
    if pg is None:
        pg = OxmlElement("w:pgNumType")
        sec._sectPr.append(pg)
    if number_format:
        pg.set(qn("w:fmt"), number_format)
    if start is not None:
        pg.set(qn("w:start"), str(start))
    return sec
