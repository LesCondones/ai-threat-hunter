"""
CLI tool for analyst review of records flagged needs_review=True.
Reads the most recent analysis_cache.json, walks the analyst through
each flagged record, and logs their decision into AnalystFeedback.
"""

import json
from data.database import create_feedback_table, insert_feedback


def load_results():
    with open("analysis_cache.json", "r") as f:
        return json.load(f)


def review_record(record):
    print("=" * 60)
    print(f"Name:     {record.get('name')}")
    print(f"Score:    {record.get('score')}")
    print(f"Tactic:   {record.get('tactic')}")
    print(f"Severity: {record.get('severity')}")
    print(f"Summary:  {record.get('summary')}")
    print()

    original_tactic = record.get('tactic')
    original_severity = record.get('severity')

    confirm = input("Is this correct? (y/n): ").strip().lower()

    if confirm == "y":
        corrected_tactic = original_tactic
        corrected_severity = original_severity
        notes = "Confirmed correct by analyst."
    else:
        corrected_tactic = input(f"Corrected tactic (blank to keep '{original_tactic}'): ").strip()
        corrected_tactic = corrected_tactic or original_tactic

        corrected_severity = input(f"Corrected severity (blank to keep '{original_severity}'): ").strip()
        corrected_severity = corrected_severity or original_severity

        notes = input("Analyst notes: ").strip()

    return original_tactic, corrected_tactic, original_severity, corrected_severity, notes


def review_flagged_records():
    create_feedback_table()
    results = load_results()

    flagged = [r for r in results if r.get("needs_review")]

    if not flagged:
        print("No records currently flagged for review.")
        return

    print(f"Found {len(flagged)} record(s) needing review.\n")

    for record in flagged:
        original_tactic, corrected_tactic, original_severity, corrected_severity, notes = review_record(record)

        jailbreak_id = record.get("jailbreak_id")

        insert_feedback(
            jailbreak_id=jailbreak_id,
            original_tactic=original_tactic,
            corrected_tactic=corrected_tactic,
            original_severity=original_severity,
            corrected_severity=corrected_severity,
            analyst_notes=notes,
        )
        print("Feedback recorded.\n")


if __name__ == "__main__":
    review_flagged_records()