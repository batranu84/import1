#!/usr/bin/env python3
"""Convert Anduin2017/HowToCook markdown recipes into normalized REMNIS JSONL.

Source repository: https://github.com/Anduin2017/HowToCook
Repository license: The Unlicense. Only files under dishes/ are scanned.
No recipe text is invented. A row is emitted only when the markdown contains
both a usable ingredient section and a numbered procedure section.
"""
from __future__ import annotations
import argparse, json, pathlib, re

COUNTRY_ID = "cn"
SOURCE_REPO = "https://github.com/Anduin2017/HowToCook"
LICENSE = "unlicense"


def clean_md(text: str) -> str:
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = text.replace("**", "").replace("__", "").replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def heading_name(line: str) -> str:
    return clean_md(re.sub(r"^#+\s*", "", line)).casefold()


def section_kind(heading: str) -> str | None:
    h = heading.casefold()
    if any(x in h for x in ("计算", "用量", "食材", "原料", "配料", "ingredients")):
        return "ingredients"
    if any(x in h for x in ("操作", "步骤", "做法", "制作", "烹饪", "instructions", "method")):
        return "steps"
    return None


def title_from(lines: list[str], path: pathlib.Path) -> str:
    for line in lines:
        if line.startswith("# "):
            title = clean_md(line[2:])
            title = re.sub(r"(?:的)?做法$", "", title).strip()
            if title and title not in {"示例菜", "模板"}:
                return title
    return path.stem


def description_from(lines: list[str]) -> str:
    after_title = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("# "):
            after_title = True
            continue
        if not after_title or not line or line.startswith("#"):
            continue
        if line.startswith(("预估", "预计", "- ", "* ")):
            continue
        text = clean_md(line)
        if len(text) >= 12:
            return text[:500]
    return ""


def parse_recipe(path: pathlib.Path, root: pathlib.Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    lines = text.splitlines()
    title = title_from(lines, path)
    if not title or "示例" in title or path.stem.casefold() == "readme":
        return None

    ingredients: list[str] = []
    steps: list[str] = []
    mode: str | None = None
    for raw in lines:
        s = raw.strip()
        if s.startswith("## "):
            mode = section_kind(heading_name(s))
            continue
        if s.startswith("### "):
            mode = None
            continue
        if mode == "ingredients":
            if re.match(r"^[-*]\s+", s):
                item = clean_md(re.sub(r"^[-*]\s+", "", s))
                if item and len(item) <= 500:
                    ingredients.append(item)
        elif mode == "steps":
            m = re.match(r"^\d+[.)、]\s*(.+)$", s)
            if m:
                step = clean_md(m.group(1))
                if step and len(step) <= 1200:
                    steps.append(step)

    ingredients = list(dict.fromkeys(ingredients))
    if len(ingredients) < 2 or len(steps) < 2:
        return None

    rel = path.relative_to(root).as_posix()
    source_url = f"{SOURCE_REPO}/blob/master/{rel}"
    category = rel.split("/")[1] if len(rel.split("/")) > 2 else ""
    return {
        "countryID": COUNTRY_ID,
        "title": title,
        "description": description_from(lines) or f"Chinese recipe from the HowToCook community cookbook: {title}.",
        "ingredients": ingredients,
        "steps": steps,
        "mealType": "main",
        "tags": ["china", "howtocook", category] if category else ["china", "howtocook"],
        "sourceTitle": "HowToCook",
        "sourceURL": source_url,
        "sourceYear": 2026,
        "author": "HowToCook contributors",
        "license": LICENSE,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, type=pathlib.Path, help="Local checkout of Anduin2017/HowToCook")
    ap.add_argument("--output", required=True, type=pathlib.Path, help="Normalized JSONL output")
    ap.add_argument("--minimum", type=int, default=119, help="Fail if fewer than this many complete rows are parsed")
    args = ap.parse_args()
    dishes = args.repo / "dishes"
    license_file = args.repo / "LICENSE"
    if not dishes.is_dir():
        raise SystemExit(f"HowToCook dishes directory not found: {dishes}")
    if not license_file.exists() or "public domain" not in license_file.read_text(encoding="utf-8", errors="ignore").casefold():
        raise SystemExit("HowToCook Unlicense/public-domain license evidence not found; refusing ingestion")

    rows = []
    seen = set()
    scanned = 0
    for path in sorted(dishes.rglob("*.md")):
        if "template" in path.parts:
            continue
        scanned += 1
        row = parse_recipe(path, args.repo)
        if not row:
            continue
        key = re.sub(r"\s+", " ", row["title"].casefold()).strip()
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"HowToCook China: scanned={scanned}, complete_distinct={len(rows)}, output={args.output}")
    if len(rows) < args.minimum:
        raise SystemExit(f"HowToCook China capacity gate failed: {len(rows)} complete recipes; requires >= {args.minimum}")


if __name__ == "__main__":
    main()
