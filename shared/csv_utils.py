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


def append_csv_row(row, file_name):
    """Append a single row to a CSV in AuditResults/, writing a header if the file is new.
    Used for incremental event logs (e.g. handset status changes) where rewriting
    the whole file each time is not appropriate."""
    ensure_audit_dir()

    file_path = AUDIT_DIR / file_name
    write_header = not file_path.exists()

    with open(file_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()), extrasaction='ignore')
        if write_header:
            writer.writeheader()
        writer.writerow(row)

    return file_path


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
