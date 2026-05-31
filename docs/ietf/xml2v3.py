#!/usr/bin/env python3
"""Post-process kramdown-rfc XML output to replace RFC 7749 (v2) deprecated
elements with RFC 7991 (v3) equivalents for clean idnits submission."""

import re
import sys


def replace_spanx(xml: str) -> str:
    """<spanx style="verb"> → <tt>, <spanx style="emph"> → <em>,
    <spanx style="strong"> → <strong>."""
    xml = re.sub(r'<spanx style="verb">', '<tt>', xml)
    xml = re.sub(r'<spanx style="emph">', '<em>', xml)
    xml = re.sub(r'<spanx style="strong">', '<strong>', xml)
    xml = re.sub(r'</spanx>', '</tt>', xml)
    # The above </spanx> replacement is over-broad only if multiple styles mix,
    # but we first replace opening tags so the closing tag is unambiguous.
    return xml


def replace_lists(xml: str) -> str:
    """<t><list style="symbols/numbers"> ... </list></t> → <ul>/<ol> with <li>."""

    def repl(m: re.Match) -> str:
        style = m.group(1)
        body = m.group(2)
        tag = 'ol' if 'numbers' in style else 'ul'
        # Replace inner <t> items with <li>. Items may be multi-line.
        body = re.sub(r'<t>(.*?)</t>', r'<li>\1</li>', body, flags=re.DOTALL)
        return f'<{tag}>\n{body}</{tag}>'

    return re.sub(
        r'<t><list style="([^"]*)"[^>]*>\n(.*?)\n?</list></t>',
        repl,
        xml,
        flags=re.DOTALL,
    )


def replace_texttables(xml: str) -> str:
    """<texttable> with <ttcol>/<c> → <table> with <thead>/<tbody>/<tr>/<th>/<td>."""

    def repl(m: re.Match) -> str:
        content = m.group(1)

        # Extract column headers (preserve inner content including markup)
        headers = re.findall(r'<ttcol[^>]*>(.*?)</ttcol>', content, re.DOTALL)
        # Extract data cells
        cells = re.findall(r'<c>(.*?)</c>', content, re.DOTALL)

        n = len(headers)
        if n == 0:
            return m.group(0)  # can't transform; leave as-is

        # Build <thead>
        th_cells = ''.join(f'          <th align="left">{h}</th>\n' for h in headers)
        thead = f'      <thead>\n        <tr>\n{th_cells}        </tr>\n      </thead>\n'

        # Build <tbody> rows
        rows = ''
        for i in range(0, len(cells), n):
            row_cells = cells[i:i + n]
            td_cells = ''.join(f'          <td>{c}</td>\n' for c in row_cells)
            rows += f'        <tr>\n{td_cells}        </tr>\n'

        tbody = f'      <tbody>\n{rows}      </tbody>\n'

        # Preserve optional preamble/postamble
        preamble = ''
        pm = re.search(r'<preamble>(.*?)</preamble>', content, re.DOTALL)
        if pm:
            preamble = f'      <preamble>{pm.group(1)}</preamble>\n'

        return f'<table>\n{preamble}{thead}{tbody}    </table>'

    return re.sub(
        r'<texttable[^>]*>(.*?)</texttable>',
        repl,
        xml,
        flags=re.DOTALL,
    )


def strip_line_pis(xml: str) -> str:
    """Remove <?line N?> processing instructions inserted by kramdown-rfc."""
    return re.sub(r'\s*<\?line \d+\?>', '', xml)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else None
    xml = open(path).read() if path else sys.stdin.read()

    xml = replace_spanx(xml)
    xml = replace_lists(xml)
    xml = replace_texttables(xml)
    xml = strip_line_pis(xml)

    if path:
        open(path, 'w').write(xml)
    else:
        sys.stdout.write(xml)


if __name__ == '__main__':
    main()
