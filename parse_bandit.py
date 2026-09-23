import json
r = json.load(open("bandit_report.json"))
res = r["results"]
print("total findings:", len(res))
for x in res:
    print("%-8s %-8s %-6s %s:%s %s" % (
        x["issue_severity"], x["issue_confidence"], x["test_id"],
        x["filename"].split("\\")[-1], x["line_number"],
        x["issue_text"][:90]))