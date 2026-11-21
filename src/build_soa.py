"""Build grc/soa.xlsx (formatted Statement of Applicability plus a summary) from grc/soa.csv, the source."""
from pathlib import Path

import pandas as pd
from openpyxl.styles import Alignment, Font, PatternFill

ROOT = Path(__file__).resolve().parent.parent
SOA = ROOT / "grc" / "soa.csv"
THEMES = {"5": "5 Organizational", "6": "6 People", "7": "7 Physical", "8": "8 Technological"}
STATUSES = ["Implemented", "Inherited", "Partial", "Planned", "Not applicable"]
FILL = {"Implemented": "C6EFCE", "Inherited": "DDEBF7", "Partial": "FFEB9C", "Planned": "F8CBAD", "Not applicable": "EDEDED"}


def load() -> pd.DataFrame:
    return pd.read_csv(SOA, dtype=str).fillna("")


def summary(soa: pd.DataFrame) -> pd.DataFrame:
    """Controls per theme and status, with totals: the table quoted in docs/06."""
    t = pd.crosstab(soa.Control.str.split(".").str[0].map(THEMES), soa.Status).reindex(columns=STATUSES, fill_value=0)
    t["Total"] = t.sum(axis=1)
    t.loc["All"] = t.sum()
    return t


def main():
    soa = load()
    with pd.ExcelWriter(ROOT / "grc" / "soa.xlsx", engine="openpyxl") as xw:
        soa.to_excel(xw, sheet_name="Statement of Applicability", index=False)
        ws = xw.sheets["Statement of Applicability"]
        for col, width in zip("ABCDEFG", (8, 44, 11, 15, 70, 50, 50)):
            ws.column_dimensions[col].width = width
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
            row[3].fill = PatternFill("solid", fgColor=FILL[row[3].value])
        for cell in ws[1]:
            cell.font = Font(bold=True)
        ws.freeze_panes = "B2"
        ws.auto_filter.ref = ws.dimensions
        summary(soa).to_excel(xw, sheet_name="Summary", index_label="Theme")
    print(f"wrote grc/soa.xlsx: {len(soa)} controls")


if __name__ == "__main__":
    main()
