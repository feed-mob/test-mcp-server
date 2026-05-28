#!/usr/bin/env python3
"""Build docs.sqlite with FTS5 from scraped markdown files.

Usage:
    python scripts/build_db.py <scraped_dir> <output_db>

Example:
    python scripts/build_db.py ../scraped data/db/docs.sqlite
"""

import json
import sqlite3
import sys
import re
from pathlib import Path


def parse_frontmatter(content: str):
    """Extract pageId, title, url from markdown frontmatter headers."""
    page_id = ""
    title = ""
    url = ""
    depth = 0

    page_id_m = re.search(r"\*\*Page ID:\*\*\s*(\d+)", content)
    if page_id_m:
        page_id = page_id_m.group(1)

    url_m = re.search(r"\*\*URL:\*\*\s*(.+)", content)
    if url_m_m := url_m:
        url = url_m.group(1).strip()

    depth_m = re.search(r"\*\*Depth:\*\*\s*(\d+)", content)
    if depth_m:
        depth = int(depth_m.group(1))

    # First # heading as title
    title_m = re.search(r"^#\s+(.+)", content, re.MULTILINE)
    if title_m:
        title = title_m.group(1).strip()

    return page_id, title, url, depth


def clean_markdown(content: str) -> str:
    """Strip frontmatter metadata lines, keep body text for search."""
    lines = content.split("\n")
    cleaned = []
    for line in lines:
        if line.strip().startswith("- **Page ID:**"):
            continue
        if line.strip().startswith("- **URL:**"):
            continue
        if line.strip().startswith("- **Depth:**"):
            continue
        if line.strip().startswith("- **Last version:**"):
            continue
        if line.strip().startswith("- **Created at:**"):
            continue
        if line.strip() == "---":
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


def build_db(scraped_dir: str, output_db: str):
    scraped_path = Path(scraped_dir)

    # Remove existing DB
    db_file = Path(output_db)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    if db_file.exists():
        db_file.unlink()

    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT,
            title TEXT,
            url TEXT,
            depth INTEGER DEFAULT 0,
            file_path TEXT UNIQUE NOT NULL,
            content TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(
            title,
            content,
            content='pages',
            content_rowid='id'
        )
    """)

    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS pages_ai AFTER INSERT ON pages BEGIN
            INSERT INTO pages_fts(rowid, title, content) VALUES (new.id, new.title, new.content);
        END
    """)

    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS pages_ad AFTER DELETE ON pages BEGIN
            INSERT INTO pages_fts(pages_fts, rowid, title, content) VALUES('delete', old.id, old.title, old.content);
        END
    """)

    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS pages_au AFTER UPDATE ON pages BEGIN
            INSERT INTO pages_fts(pages_fts, rowid, title, content) VALUES('delete', old.id, old.title, old.content);
            INSERT INTO pages_fts(rowid, title, content) VALUES (new.id, new.title, new.content);
        END
    """)

    # Walk all .md files
    md_files = sorted(scraped_path.rglob("*.md"))
    count = 0
    for md_file in md_files:
        rel_path = md_file.relative_to(scraped_path)
        content = md_file.read_text(encoding="utf-8", errors="replace")

        page_id, title, url, depth = parse_frontmatter(content)
        body = clean_markdown(content)

        if not title:
            # Derive title from filename
            title = md_file.stem

        cur.execute(
            "INSERT OR IGNORE INTO pages (page_id, title, url, depth, file_path, content) VALUES (?, ?, ?, ?, ?, ?)",
            (page_id, title, url, depth, str(rel_path), body),
        )
        count += 1

    conn.commit()

    # Verify
    cur.execute("SELECT COUNT(*) FROM pages")
    row_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM pages_fts")
    fts_count = cur.fetchone()[0]

    print(f"Inserted {count} markdown files into {output_db}")
    print(f"Pages table: {row_count} rows, FTS index: {fts_count} rows")

    # Quick FTS test
    cur.execute("SELECT rowid, title FROM pages_fts WHERE pages_fts MATCH ? LIMIT 3", ("campaign",))
    results = cur.fetchall()
    print(f"FTS test 'campaign': {len(results)} results (showing up to 3)")
    for r in results:
        print(f"  rowid={r[0]}, title={r[1]}")

    conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <scraped_dir> <output_db>")
        sys.exit(1)
    build_db(sys.argv[1], sys.argv[2])