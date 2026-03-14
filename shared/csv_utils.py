import csv
from pathlib import Path


AUDIT_DIR = Path("AuditResults")


def ensure_audit_dir():
    AUDIT_DIR.mkdir(exist_ok=True)


def build_csv(datalist, audit_file_name, date_stamp):
    """Write user audit data to a timestamped CSV in AuditResults/."""
    ensure_audit_dir()

    if not datalist:
        print("No data to write to CSV.")
        return

    file_name = f'{audit_file_name}-{date_stamp}.csv'
    file_path = AUDIT_DIR / file_name

    fieldnames = list(datalist[0].keys())
    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(datalist)

    print(f'Audit written to: {file_path}')


def cq_build_csv(datalist, audit_file_name, date_stamp):
    """Write call queue audit data to a timestamped CSV in AuditResults/."""
    ensure_audit_dir()

    if not datalist:
        print("No call queue data to write to CSV.")
        return

    file_name = f'{audit_file_name}-CallQueueDetails-{date_stamp}.csv'
    file_path = AUDIT_DIR / file_name

    fieldnames = list(datalist[0].keys())
    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(datalist)

    print(f'Call queue details written to: {file_path}')
