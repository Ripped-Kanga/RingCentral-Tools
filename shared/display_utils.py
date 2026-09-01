"""Display views and formatting helpers for the live monitor modules.

Two interchangeable views, both taking pre-built row dicts:

- PlainDisplay: one printed line per event, driven by a line-format callable.
- LiveTableDisplay: an in-place updating rich table, driven by a column spec —
  a list of (header, column_kwargs, cell_fn, style_fn_or_None) tuples where
  cell_fn(row) returns the cell text and style_fn(row) an optional rich style.

Both expose the same surface: start(), stop(), status(text), events(rows).
"""

import datetime
from collections import deque

try:
    from rich.console import Group
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Rows kept visible in the live table view.
TABLE_ROWS = 18


def fmt_local(iso_str):
    """Convert an ISO 8601 UTC timestamp from the API to local time for display."""
    if not iso_str:
        return ''
    try:
        dt = datetime.datetime.fromisoformat(str(iso_str).replace('Z', '+00:00'))
        return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return str(iso_str)


def fmt_endpoint(name, number):
    if name and number:
        return f'{name} ({number})'
    return name or number or '?'


class PlainDisplay:
    """Scrolling one-line-per-event output. Suits logging, tmux scrollback,
    and terminals where a repainting live table is unwelcome."""

    def __init__(self, line_fn):
        self._line_fn = line_fn

    def start(self):
        pass

    def stop(self):
        pass

    def status(self, text):
        print(f'► [{datetime.datetime.now().strftime("%H:%M:%S")}] {text}')

    def events(self, rows):
        for row in rows:
            print(self._line_fn(row))


class LiveTableDisplay:
    """Live TUI table (rich) showing the most recent events with a status bar."""

    def __init__(self, title, subtitle, csv_note, columns, empty_caption='Waiting for events...'):
        self._title = title
        self._subtitle = subtitle
        self._csv_note = csv_note
        self._columns = columns
        self._empty_caption = empty_caption
        self._events = deque(maxlen=TABLE_ROWS)
        self._status_text = 'Starting...'
        self._count = 0
        self._live = Live(self._render(), refresh_per_second=4)

    def start(self):
        self._live.start()

    def stop(self):
        self._live.stop()

    def status(self, text):
        self._status_text = text
        self._live.update(self._render())

    def events(self, rows):
        self._events.extend(rows)
        self._count += len(rows)
        self._live.update(self._render())

    def _render(self):
        header = Text()
        header.append(self._title, style='bold')
        header.append(f' — {self._subtitle}\n', style='dim')
        header.append(self._status_text)
        header.append(f'  |  Events: {self._count}')
        if self._csv_note:
            header.append(f'  |  CSV: {self._csv_note}', style='dim')
        header.append('\nPress CTRL+C to stop monitoring.', style='dim')

        table = Table(expand=True)
        for col_header, col_kwargs, _, _ in self._columns:
            table.add_column(col_header, **col_kwargs)
        if not self._events:
            table.caption = self._empty_caption
        for row in self._events:
            cells = []
            for _, _, cell_fn, style_fn in self._columns:
                value = str(cell_fn(row))
                style = style_fn(row) if style_fn else ''
                cells.append(Text(value, style=style) if style else value)
            table.add_row(*cells)
        return Group(header, table)
