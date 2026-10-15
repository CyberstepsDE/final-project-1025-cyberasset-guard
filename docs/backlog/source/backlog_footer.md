## 5. Importing into Jira

No issues have been created. To import `jira-import.csv` (Jira Cloud, **System → External system import → CSV**,
or **Project settings → Import issues**):

1. Choose the target project (not invented here — select your project). Encoding **UTF-8**, delimiter `,`.
2. Map the columns:

   | CSV column | Jira field |
   |---|---|
   | `Issue ID` | **Issue Id** (used only to build parent/link relations inside the file) |
   | `Parent ID` | **Parent Id** (Epic → Story/Task/Bug, Story → Sub-task) |
   | `Issue Type` | Issue Type (Epic, Story, Task, Bug, Sub-task) |
   | `Summary` | Summary |
   | `Epic Name` | Epic Name (company-managed projects only; ignore otherwise) |
   | `Description` | Description (Jira wiki markup: acceptance criteria, dependencies, security, testing) |
   | `Priority` | Priority |
   | `Story Points` | Story Points / Story point estimate |
   | `Labels` (repeated) | Labels |
   | `Blocked By` (repeated) | **Link: is blocked by** (refers to `Issue ID` values in the same file) |

3. Run the importer's validation first and fix any unmapped issue type or priority.
4. Before importing, search the project for `labels = cyberasset-guard` to avoid creating duplicates.

Acceptance criteria are part of the description because a dedicated acceptance-criteria field is not
standard in Jira. If your project has one, copy the "Acceptance criteria" block into it after import.

### When Jira access becomes available

With a Jira connector or API token, the next steps are: confirm the project key, issue types and required
fields; review this structure with the team; create the epics, then the stories with parent links, then the
"is blocked by" links; finally report the created keys. Nothing will be created without that review.

## 6. Regenerating this backlog

`BACKLOG.md` and `jira-import.csv` are generated from one data file, so they cannot drift apart.
Edit `source/backlog_data.py` (or the header/footer Markdown) and regenerate instead of editing the outputs by hand:

```bash
python -I docs/backlog/source/generate_backlog.py docs/backlog
```
