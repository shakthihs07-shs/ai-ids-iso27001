"""Build grc/soa.xlsx from the two sources in grc/: soa.csv (Statement of Applicability) and
risk_register_live.csv (risks of the live service). Adds computed risk scores and, per control, the risks it treats."""
from pathlib import Path

import pandas as pd
from openpyxl.styles import Alignment, Font, PatternFill

from build_risk_register import band  # one scoring method for both registers

ROOT = Path(__file__).resolve().parent.parent
SOA = ROOT / "grc" / "soa.csv"
RISKS = ROOT / "grc" / "risk_register_live.csv"
ACCEPTANCE = 9  # residual score at or below which a risk may be accepted, as in docs/03
THEMES = {"5": "5 Organizational", "6": "6 People", "7": "7 Physical", "8": "8 Technological"}
STATUSES = ["Implemented", "Inherited", "Partial", "Planned", "Not applicable"]
FILL = {"Implemented": "C6EFCE", "Inherited": "DDEBF7", "Partial": "FFEB9C", "Planned": "F8CBAD", "Not applicable": "EDEDED"}


def load() -> pd.DataFrame:
    return pd.read_csv(SOA, dtype=str).fillna("")


def load_risks() -> pd.DataFrame:
    """The live-service risk register with inherent and residual scores and ratings."""
    r = pd.read_csv(RISKS, dtype={"Open treatment": str}).fillna("")
    r.insert(6, "Inherent score", r.Likelihood * r.Impact)
    r.insert(7, "Inherent rating", r["Inherent score"].map(band))
    r.insert(11, "Residual score", r["Residual likelihood"] * r["Residual impact"])
    r.insert(12, "Residual rating", r["Residual score"].map(band))
    return r


def controls(cell: str) -> list[str]:
    return [c.strip() for c in cell.split(",") if c.strip()]


def risks_per_control(risks: pd.DataFrame) -> dict[str, str]:
    """Control -> the live-service risks it treats, e.g. {'8.20': 'LR01'}."""
    out: dict[str, list[str]] = {}
    for rid, cell in zip(risks["Risk ID"], risks["Annex A controls"]):
        for c in controls(cell):
            out.setdefault(c, []).append(rid)
    return {c: ", ".join(ids) for c, ids in out.items()}


def summary(soa: pd.DataFrame) -> pd.DataFrame:
    """Controls per theme and status, with totals: the table quoted in docs/06."""
    t = pd.crosstab(soa.Control.str.split(".").str[0].map(THEMES), soa.Status).reindex(columns=STATUSES, fill_value=0)
    t["Total"] = t.sum(axis=1)
    t.loc["All"] = t.sum()
    return t


def main():
    soa, risks = load(), load_risks()
    linked = risks_per_control(risks)
    sheet = soa.assign(**{"Risks treated (live service)": soa.Control.map(linked).fillna("baseline / legal")})
    with pd.ExcelWriter(ROOT / "grc" / "soa.xlsx", engine="openpyxl") as xw:
        sheet.to_excel(xw, sheet_name="Statement of Applicability", index=False)
        ws = xw.sheets["Statement of Applicability"]
        for col, width in zip("ABCDEFGH", (8, 44, 11, 15, 70, 50, 50, 18)):
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
        risks.to_excel(xw, sheet_name="Live risk register", index=False)
        ws = xw.sheets["Live risk register"]
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        for cell in ws[1]:
            cell.font = Font(bold=True)
        ws.freeze_panes = "C2"
    print(f"wrote grc/soa.xlsx: {len(soa)} controls, {len(risks)} live-service risks")


if __name__ == "__main__":
    main()
