"""Generate BACKLOG.md and jira-import.csv from backlog_data.py.

Usage: python -I generate_backlog.py <output_dir>
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from backlog_data import EPICS, ITEMS  # noqa: E402

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)

BY_ID = {i["id"]: i for i in ITEMS}
EPIC_BY_ID = {e["id"]: e for e in EPICS}
PHASES = {
    0: "Phase 0 - Close critical gaps now",
    1: "Phase 1 - Foundation and hardening",
    2: "Phase 2 - Asset Monitoring (next development step)",
    3: "Phase 3 - Vulnerability Management",
    4: "Phase 4 - Context-Aware Risk Engine",
    5: "Phase 5 - Remediation, verification and future enhancements",
}
CATEGORY = {"remaining": "Remaining work", "review": "Implemented, awaiting review/merge",
            "tech-debt": "Technical debt", "future": "Future enhancement"}

# --- sanity checks -----------------------------------------------------------------
for item in ITEMS:
    assert item["parent"] in EPIC_BY_ID or item["parent"] in BY_ID, item["id"]
    for dep in item["deps"]:
        assert dep in BY_ID, (item["id"], dep)
    if item["type"] != "Sub-task":
        assert item["ac"], item["id"]


def epic_of(item):
    p = item["parent"]
    return p if p in EPIC_BY_ID else BY_ID[p]["parent"]


def title(id_):
    return f"{id_} {BY_ID[id_]['title']}" if id_ in BY_ID else id_


# --- Jira CSV ------------------------------------------------------------------------

def wiki(item):
    parts = []
    if item["story"]:
        parts += ["h3. User story / objective", item["story"]]
    parts += ["h3. Description", item["description"]]
    if item["value"]:
        parts += ["h3. Business / technical value", item["value"]]
    parts += ["h3. Acceptance criteria", "\n".join(f"* {a}" for a in item["ac"])]
    if item["deps"]:
        parts += ["h3. Dependencies", "\n".join(f"* {title(d)}" for d in item["deps"])]
    if item["security"]:
        parts += ["h3. Security considerations", item["security"]]
    if item["testing"]:
        parts += ["h3. Testing requirements", item["testing"]]
    meta = [f"Backlog ref: {item['id']}", f"Category: {CATEGORY[item['category']]}",
            f"Phase: {PHASES[item['phase']]}"]
    if item["sp"] is not None:
        meta.append(f"Story points: {item['sp']} (estimate)")
    parts += ["h3. Planning", "\n".join(f"* {m}" for m in meta)]
    return "\n\n".join(parts)


max_labels = max(len(i["labels"]) + 1 for i in ITEMS)
max_deps = max(len(i["deps"]) for i in ITEMS)
header = (["Issue ID", "Parent ID", "Issue Type", "Summary", "Epic Name", "Description", "Priority",
           "Story Points"] + ["Labels"] * max_labels + ["Blocked By"] * max_deps)
rows = []
for e in EPICS:
    desc = e["description"] + "\n\n* Backlog ref: " + e["id"]
    rows.append([e["id"], "", "Epic", e["title"], e["title"], desc, "", ""]
                + ["cyberasset-guard"] + [""] * (max_labels - 1) + [""] * max_deps)
order = sorted(ITEMS, key=lambda i: (list(EPIC_BY_ID).index(epic_of(i)), i["type"] == "Sub-task"))
# sub-tasks directly after their parent story
stories = [i for i in order if i["type"] != "Sub-task"]
ordered = []
for s in stories:
    ordered.append(s)
    ordered += [i for i in ITEMS if i["type"] == "Sub-task" and i["parent"] == s["id"]]
for i in ordered:
    labels = ["cyberasset-guard"] + i["labels"]
    rows.append([i["id"], i["parent"], i["type"], i["title"], "", wiki(i), i["priority"],
                 "" if i["sp"] is None else str(i["sp"])]
                + labels + [""] * (max_labels - len(labels))
                + i["deps"] + [""] * (max_deps - len(i["deps"])))

with (OUT / "jira-import.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh, quoting=csv.QUOTE_ALL)
    w.writerow(header)
    w.writerows(rows)

# --- Markdown ---------------------------------------------------------------------------

def md_story(i):
    sp = f"{i['sp']} *(estimate)*" if i["sp"] is not None else "–"
    deps = ", ".join(f"`{d}`" for d in i["deps"]) or "none"
    lines = [f"#### {i['id']} · {i['type']} · {i['title']}", "",
             f"| Priority | Story points | Category | Phase | Depends on |",
             f"|---|---|---|---|---|",
             f"| {i['priority']} | {sp} | {CATEGORY[i['category']]} | {i['phase']} | {deps} |", ""]
    if i["story"]:
        lines += [f"**User story / objective:** {i['story']}", ""]
    lines += [f"**Description:** {i['description']}", ""]
    if i["value"]:
        lines += [f"**Value:** {i['value']}", ""]
    lines += ["**Acceptance criteria**", ""] + [f"- [ ] {a}" for a in i["ac"]] + [""]
    if i["security"]:
        lines += [f"**Security:** {i['security']}", ""]
    if i["testing"]:
        lines += [f"**Testing:** {i['testing']}", ""]
    subs = [s for s in ITEMS if s["type"] == "Sub-task" and s["parent"] == i["id"]]
    if subs:
        lines += ["**Sub-tasks**", ""]
        for s in subs:
            lines += [f"- `{s['id']}` {s['title']} — {s['description']} "
                      f"(AC: {'; '.join(s['ac'])})"]
        lines += [""]
    return "\n".join(lines)


top = [i for i in ITEMS if i["type"] != "Sub-task"]
sp_by_epic = defaultdict(int)
count_by_epic = defaultdict(int)
for i in top:
    sp_by_epic[epic_of(i)] += i["sp"] or 0
    count_by_epic[epic_of(i)] += 1

md = [Path(__file__).with_name("backlog_header.md").read_text(encoding="utf-8"), ""]

md += ["## 2. Proposed Jira hierarchy", "",
       "| Epic | Items | Story points *(estimate)* | Scope |", "|---|---|---|---|"]
for e in EPICS:
    md.append(f"| **{e['id']} {e['title']}** | {count_by_epic[e['id']]} | {sp_by_epic[e['id']]} | {e['description']} |")
md += ["", f"Total: {len(EPICS)} epics, {len(top)} stories/tasks/bugs, "
           f"{sum(1 for i in ITEMS if i['type'] == 'Sub-task')} sub-tasks, "
           f"{sum(sp_by_epic.values())} story points *(estimate)*.", ""]

md += ["```text"]
for e in EPICS:
    md.append(f"{e['id']}  {e['title']}")
    for i in [x for x in ITEMS if x["parent"] == e["id"]]:
        md.append(f"  ├─ {i['id']:<6} [{i['type']}] {i['title']}")
        for s in [x for x in ITEMS if x["parent"] == i["id"]]:
            md.append(f"  │    └─ {s['id']:<7} [Sub-task] {s['title']}")
md += ["```", ""]

md += ["## 3. Recommended implementation order and dependencies", ""]
for ph, name in PHASES.items():
    items = [i for i in top if i["phase"] == ph]
    md += [f"### {name}", "", "| Ref | Type | Title | Priority | SP *(est.)* | Depends on |", "|---|---|---|---|---|---|"]
    for i in sorted(items, key=lambda x: ["Highest", "High", "Medium", "Low"].index(x["priority"])):
        md.append(f"| `{i['id']}` | {i['type']} | {i['title']} | {i['priority']} | {i['sp'] or '–'} | "
                  f"{', '.join(i['deps']) or '–'} |")
    md.append("")
md += ["```mermaid", "flowchart LR"]
for i in top:
    for d in i["deps"]:
        if BY_ID[d]["type"] != "Sub-task":
            md.append(f"  {d.replace('.', '_')}[{d}] --> {i['id'].replace('.', '_')}[{i['id']}]")
md += ["```", ""]

md += ["## 4. Detailed stories and acceptance criteria", "",
       "Story points are **estimates** (Fibonacci, relative to `S1.1` = 3). Priorities use Jira's default scheme.", ""]
for e in EPICS:
    md += [f"### {e['id']} {e['title']}", "", e["description"], ""]
    for i in [x for x in ITEMS if x["parent"] == e["id"]]:
        md += [md_story(i), "---", ""]

md.append(Path(__file__).with_name("backlog_footer.md").read_text(encoding="utf-8"))
(OUT / "BACKLOG.md").write_text("\n".join(md), encoding="utf-8")

print(f"epics={len(EPICS)} items={len(top)} subtasks={len(ITEMS) - len(top)} "
      f"sp={sum(sp_by_epic.values())} csv_rows={len(rows)}")
for e in EPICS:
    print(f"  {e['id']}: {count_by_epic[e['id']]} items, {sp_by_epic[e['id']]} SP")
