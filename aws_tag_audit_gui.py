#!/usr/bin/env python3
"""
aws_tag_audit_gui.py - Tkinter front end for aws_tag_audit.py

  1. Connect with a profile -> enabled regions load into a checklist
  2. Pick regions, the tag keys you require, and (optionally) services
  3. Scan -> table of resources, one column per required tag key
  4. Select rows, type a value, "Set on selected" (or double-click a cell)
  5. "Apply pending" writes the tags (dry-run available)

Tag keys can be added/removed AFTER a scan; the table is re-evaluated
instantly because the scan keeps every resource's full tag set.

Needs only Python (with Tk, included in the standard Windows/macOS installers) + boto3.
"""

import csv
import datetime as _dt
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from collections import Counter, defaultdict
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import font as tkfont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aws_tag_audit as core  # noqa: E402

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform.startswith("win")
MONO_FAMILY = "Menlo" if IS_MAC else ("Consolas" if IS_WIN else "DejaVu Sans Mono")
MONO = (MONO_FAMILY, 11 if IS_MAC else 9)
MONO_BIG = (MONO_FAMILY, 12 if IS_MAC else 10)
MOD = "Command" if IS_MAC else "Control"  # select-all shortcut modifier

MISSING = "✗ missing"
EMPTY = "✗ (empty)"
ARROW = "→ "


# ---------------------------------------------------------------------------
# Credentials: paste the same lines you'd run in a shell (what the AWS access
# portal's "Command line or programmatic access" page gives you) and they are
# written into this process's os.environ. boto3 reads env credentials when a
# Session is created, so reconnecting picks them up - no restart. Values live
# in memory only; nothing is written to disk.
# ---------------------------------------------------------------------------
_ENV_ASSIGN_RES = (
    re.compile(r"^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$"),      # bash/zsh/sh
    re.compile(r"^\s*set\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.I),   # cmd.exe
    re.compile(r"^\s*\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", re.I),   # PowerShell
    re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$"),               # bare KEY=VALUE
)
CRED_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
SECRET_KEYS = ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


def _strip_env_quotes(val):
    val = val.strip()
    if val.endswith(";"):
        val = val[:-1].rstrip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1]
    return val


def parse_env_assignments(text):
    """Parse pasted `export K=V` / `set K=V` / `$env:K="V"` / `K=V` lines into a dict.
    Blank lines and # comments are ignored. Raises ValueError listing unparseable lines."""
    out, bad = {}, []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "REM ", "rem ")):
            continue
        for rx in _ENV_ASSIGN_RES:
            m = rx.match(line)
            if m:
                out[m.group(1)] = _strip_env_quotes(m.group(2))
                break
        else:
            bad.append(raw.rstrip())
    if bad:
        raise ValueError("Couldn't parse these line(s):\n  " + "\n  ".join(bad))
    return out


def mask(k, v):
    if k in SECRET_KEYS:
        return "%s (%d chars)" % (k, len(v))
    if k == "AWS_ACCESS_KEY_ID":
        return "%s=%s...%s" % (k, v[:4], v[-4:]) if len(v) > 8 else k
    return "%s=%s" % (k, v)


class CheckList(ttk.Frame):
    """Scrollable list of checkboxes."""

    def __init__(self, parent, height=160):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, height=height, highlightthickness=0, borderwidth=0)
        sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for w in (self.canvas, self.inner):
            w.bind("<Enter>", lambda e: self._bind_wheel(True))
            w.bind("<Leave>", lambda e: self._bind_wheel(False))
        self.vars = {}

    def _bind_wheel(self, on):
        # Windows/macOS send <MouseWheel> (delta 120 per notch on Windows, small values on macOS);
        # X11/Linux sends Button-4/5.
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            if on:
                self.canvas.bind_all(seq, self._wheel)
            else:
                self.canvas.unbind_all(seq)

    def _wheel(self, e):
        if getattr(e, "num", None) in (4, 5):
            step = -1 if e.num == 4 else 1
        else:
            step = int(-e.delta / 120) or (-1 if e.delta > 0 else 1)
        self.canvas.yview_scroll(step, "units")

    def set_items(self, names, checked=True, cols=2, labels=None):
        for w in self.inner.winfo_children():
            w.destroy()
        self.vars = {}
        for i, n in enumerate(names):
            v = tk.BooleanVar(value=checked(n) if callable(checked) else checked)
            ttk.Checkbutton(self.inner, text=(labels or {}).get(n, n), variable=v).grid(
                row=i // cols, column=i % cols, sticky="w", padx=(2, 10))
            self.vars[n] = v

    def selected(self):
        return [n for n, v in self.vars.items() if v.get()]

    def set_all(self, val):
        for v in self.vars.values():
            v.set(val)


class TypeTree(ttk.Frame):
    """Checkable tree of resource types, grouped by service. Click toggles; groups toggle all children."""
    ON, OFF, PART = "☑ ", "☐ ", "▣ "

    def __init__(self, parent, height=9):
        super().__init__(parent)
        self.tv = ttk.Treeview(self, show="tree", height=height, selectmode="browse")
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=sb.set)
        self.tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tv.bind("<Button-1>", self._click)
        self.state, self.base, self.names = {}, {}, {}

    def load(self, collectors):
        old = dict(self.state)
        opened = {i for i in self._all_iids() if self.tv.item(i, "open")}
        self.tv.delete(*self.tv.get_children())
        self.state, self.base, self.names = {}, {}, {}
        groups = defaultdict(list)
        for name, group, scope, _ in collectors:
            if name != "tagging-api":
                groups[group].append((name, scope))
        order = sorted(g for g in groups if g != core.CUSTOM_GROUP) + ([core.CUSTOM_GROUP] if core.CUSTOM_GROUP in groups else [])
        for g in order:
            items = groups[g]
            if len(items) == 1 and items[0][0] == g:
                parent = ""
            else:
                parent = "G:" + g
                self.base[parent] = "★ custom (yours)" if g == core.CUSTOM_GROUP else g
                self.tv.insert("", "end", iid=parent, open=parent in opened or g == core.CUSTOM_GROUP)
            for name, scope in sorted(items):
                iid = "L:" + name
                short = name.split(":", 1)[1] if (":" in name and g != core.CUSTOM_GROUP and parent) else name
                fine = not core.is_main_type(name)
                self.base[iid] = short + ("  (global)" if scope == "global" else "") + ("  · fine-grained" if fine else "")
                self.names[iid] = name
                self.state[name] = old.get(name, not fine)
                self.tv.insert(parent, "end", iid=iid)
        self._render()

    def _all_iids(self):
        out = []
        for top in self.tv.get_children():
            out.append(top)
            out.extend(self.tv.get_children(top))
        return out

    def _render(self):
        for iid in self._all_iids():
            if iid in self.names:
                mark = self.ON if self.state[self.names[iid]] else self.OFF
            else:
                kids = [self.state[self.names[c]] for c in self.tv.get_children(iid)]
                mark = self.ON if all(kids) else (self.OFF if not any(kids) else self.PART)
            self.tv.item(iid, text=mark + self.base[iid])

    def _click(self, e):
        iid = self.tv.identify_row(e.y)
        if not iid or "indicator" in self.tv.identify_element(e.x, e.y):
            return
        if iid in self.names:
            n = self.names[iid]
            self.state[n] = not self.state[n]
        else:
            kids = [self.names[c] for c in self.tv.get_children(iid)]
            target = not all(self.state[k] for k in kids)
            for k in kids:
                self.state[k] = target
        self._render()

    def selected(self):
        return [n for n, v in self.state.items() if v]

    def all_selected(self):
        return all(self.state.values())

    def set_all(self, v):
        for n in self.state:
            self.state[n] = v
        self._render()

    def main_only(self):
        for n in self.state:
            self.state[n] = core.is_main_type(n)
        self._render()

    def focused_name(self):
        return self.names.get(self.tv.focus())


class CustomTypeDialog(tk.Toplevel):
    """Create / edit / test a custom resource type defined by an AWS CLI command."""

    FIELDS = [("items_path", "Items path", "where the list is, e.g. Reservations.Instances (blank = auto)"),
              ("id_field", "ID field", "e.g. InstanceId (blank = auto)"),
              ("name_field", "Name field", "blank = Name tag, else auto"),
              ("arn_field", "ARN field", "e.g. FunctionArn (blank = auto)"),
              ("arn_template", "ARN template", "if no ARN in the output, e.g. arn:{partition}:es:{region}:{account}:domain/{DomainName}")]

    def __init__(self, app, spec=None):
        super().__init__(app)
        self.app, self.orig = app, spec
        self.title("Edit resource type" if spec else "New resource type")
        self.geometry("980x760+%d+%d" % (app.winfo_rootx() + 60, app.winfo_rooty() + 30))
        self.transient(app)
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="Start from example:").grid(row=0, column=0, sticky="w")
        self.example = ttk.Combobox(f, state="readonly", values=["(none)"] + [e["name"] for e in core.EXAMPLE_TYPES])
        self.example.set("(none)")
        self.example.grid(row=0, column=1, sticky="w", pady=2)
        self.example.bind("<<ComboboxSelected>>", self._use_example)

        ttk.Label(f, text="Name:").grid(row=1, column=0, sticky="w")
        self.name = ttk.Entry(f, width=40)
        self.name.grid(row=1, column=1, sticky="w", pady=2)
        ttk.Label(f, text="service:type, shown in the Type column, e.g. sagemaker:notebook-instance", foreground="#666").grid(row=2, column=1, sticky="w")

        ttk.Label(f, text="AWS command:").grid(row=3, column=0, sticky="nw", pady=(6, 0))
        self.cmd = tk.Text(f, height=3, font=MONO_BIG, wrap="word")
        self.cmd.grid(row=3, column=1, sticky="ew", pady=(6, 0))
        ttk.Label(f, text="A read-only list/describe/get command, written like the AWS CLI. It runs through boto3 (no AWS CLI needed) "
                          "in every scanned region; --region/--profile/--output/--query are ignored.",
                  foreground="#666", wraplength=780, justify="left").grid(row=4, column=1, sticky="w")

        sc = ttk.Frame(f)
        sc.grid(row=5, column=1, sticky="w", pady=4)
        ttk.Label(f, text="Scope:").grid(row=5, column=0, sticky="w")
        self.scope = tk.StringVar(value="regional")
        ttk.Radiobutton(sc, text="Regional (run in each scanned region)", value="regional", variable=self.scope).pack(side="left")
        ttk.Radiobutton(sc, text="Global (run once)", value="global", variable=self.scope).pack(side="left", padx=10)

        adv = ttk.LabelFrame(f, text=" How to read the output (blank = auto-detect; Test fills these in) ", padding=6)
        adv.grid(row=6, column=0, columnspan=2, sticky="ew", pady=6)
        adv.columnconfigure(1, weight=1)
        self.entries = {}
        for r, (k, label, hint) in enumerate(self.FIELDS):
            ttk.Label(adv, text=label + ":").grid(row=r, column=0, sticky="w")
            e = ttk.Entry(adv, width=60)
            e.grid(row=r, column=1, sticky="ew", pady=1)
            ttk.Label(adv, text=hint, foreground="#777").grid(row=r, column=2, sticky="w", padx=6)
            self.entries[k] = e
        ttk.Label(adv, text="ARN template variables: {partition} {region} {account} {id} {name} and any top-level field of the item, e.g. {DomainName}",
                  foreground="#777").grid(row=len(self.FIELDS), column=0, columnspan=3, sticky="w")

        tr = ttk.Frame(f)
        tr.grid(row=7, column=0, columnspan=2, sticky="ew")
        ttk.Label(tr, text="Test in region:").pack(side="left")
        regions = app.regions.selected() or list(app.regions.vars) or ([app.ctx.start_region] if app.ctx else [])
        self.test_region = ttk.Combobox(tr, values=regions, width=18)
        self.test_region.set(app.ctx.start_region if app.ctx and app.ctx.start_region in regions else (regions[0] if regions else ""))
        self.test_region.pack(side="left", padx=4)
        self.test_btn = ttk.Button(tr, text="Test", command=self.test)
        self.test_btn.pack(side="left")
        self.status = ttk.Label(tr, text="" if app.ctx else "Connect in the main window to run a test (checking syntax works offline).", foreground="#a60")
        self.status.pack(side="left", padx=8)

        pv = ttk.Frame(f)
        pv.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=6)
        f.rowconfigure(8, weight=1)
        self.preview = tk.Text(pv, font=MONO, wrap="none", state="disabled")
        ys = ttk.Scrollbar(pv, orient="vertical", command=self.preview.yview)
        xs = ttk.Scrollbar(pv, orient="horizontal", command=self.preview.xview)
        self.preview.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.preview.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        pv.rowconfigure(0, weight=1)
        pv.columnconfigure(0, weight=1)

        bb = ttk.Frame(f)
        bb.grid(row=9, column=0, columnspan=2, sticky="e")
        ttk.Button(bb, text="Check syntax", command=self.check).pack(side="left", padx=4)
        ttk.Button(bb, text="Save", style="Big.TButton", command=self.save).pack(side="left", padx=4)
        ttk.Button(bb, text="Cancel", command=self.destroy).pack(side="left")
        if spec:
            self._fill(spec)
        self.name.focus_set()

    def _fill(self, spec):
        self.name.delete(0, "end")
        self.name.insert(0, spec.get("name", ""))
        self.cmd.delete("1.0", "end")
        self.cmd.insert("1.0", spec.get("command", ""))
        self.scope.set(spec.get("scope", "regional"))
        for k, e in self.entries.items():
            e.delete(0, "end")
            e.insert(0, spec.get(k, ""))

    def _use_example(self, _e=None):
        ex = next((e for e in core.EXAMPLE_TYPES if e["name"] == self.example.get()), None)
        if ex:
            self._fill(ex)

    def spec(self):
        s = {"name": self.name.get().strip(), "command": " ".join(self.cmd.get("1.0", "end").split()),
             "scope": self.scope.get()}
        for k, e in self.entries.items():
            if e.get().strip():
                s[k] = e.get().strip()
        return s

    def _show(self, text, color="#000"):
        self.preview.configure(state="normal", foreground=color)
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", text)
        self.preview.configure(state="disabled")

    def _parse(self):
        s = self.spec()
        service, op, params, warns = core.parse_cli_command(s["command"])
        core.check_read_only(op)
        return s, service, op, params, warns

    def check(self):
        try:
            s, service, op, params, warns = self._parse()
        except ValueError as e:
            self._show("PROBLEM WITH THE COMMAND:\n\n" + str(e), "#b00")
            return None
        msg = "Command OK  ->  boto3 %s.%s(%s)\n" % (service, core.xform_name(op), json.dumps(params) if params else "")
        msg += "".join("note: %s\n" % w for w in warns)
        self._show(msg + "\nClick Test to run it and see what it finds.")
        return s

    def test(self):
        s = self.check()
        if s is None:
            return
        if not self.app.ctx:
            self.status.configure(text="Connect in the main window first.")
            return
        if self.app.busy:
            self.status.configure(text="Busy - wait for the current scan/apply to finish.")
            return
        ctx = self.app.ctx
        region = ctx.home_region if s["scope"] == "global" else (self.test_region.get().strip() or ctx.start_region)
        self.status.configure(text="Running in %s..." % region)

        def work():
            pages = core.run_cli_command(ctx, s["command"], region)
            return core.build_custom(ctx, s, region, pages)

        def done(result):
            if not self.winfo_exists():
                return
            rows, info = result
            self.status.configure(text="%d items in %s" % (info["count"], region))
            filled = []
            for k in ("items_path", "id_field", "name_field", "arn_field"):
                e = self.entries[k]
                if not e.get().strip() and info.get(k):
                    e.insert(0, info[k])
                    filled.append(k)
            out = ["%d items in %s" % (info["count"], region),
                   "Items path : %s" % (info["items_path"] or "(top level)"),
                   "ID field   : %s" % (info["id_field"] or "-"),
                   "Name field : %s" % (info["name_field"] or "(Name tag)"),
                   "ARN        : %s" % (("template " + s["arn_template"]) if s.get("arn_template") else (info["arn_field"] or "-")),
                   "Tags       : %s" % info["tags_source"]]
            if filled:
                out.append("(auto-detected values were filled in above: %s - check them, then Save)" % ", ".join(filled))
            out += ["WARNING: " + p for p in info["problems"]]
            out.append("")
            out.append("%-34s %-28s %-70s %s" % ("ID", "NAME", "ARN", "TAGS"))
            for r in rows[:30]:
                out.append("%-34s %-28s %-70s %s" % (r["id"][:34], r["name"][:28], r["arn"][:70],
                                                     ", ".join("%s=%s" % kv for kv in sorted(r["tags"].items()))[:120]))
            if len(rows) > 30:
                out.append("... %d more" % (len(rows) - 30))
            if info["first_item"] is not None:
                out += ["", "--- first item, raw (use these field names above) ---",
                        json.dumps(info["first_item"], indent=2, default=str)[:4000]]
            self._show("\n".join(out), "#b00" if info["problems"] and info["count"] else "#000")
        self.app._bg(work, done)

    def save(self):
        s = self.spec()
        existing = [t["name"] for t in self.app.custom_types if not self.orig or t["name"] != self.orig["name"]]
        try:
            core.validate_custom_spec(s, existing)
        except ValueError as e:
            messagebox.showwarning("Can't save", str(e), parent=self)
            return
        self.app.save_custom(s, self.orig["name"] if self.orig else None)
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AWS Tag Audit")
        w = min(1360, self.winfo_screenwidth() - 40)
        h = min(860, self.winfo_screenheight() - 80)
        self.geometry("%dx%d+20+20" % (w, h))
        self.minsize(1000, 640)
        self.q = queue.Queue()
        self.ctx = None
        self.resources = []        # list of resource dicts from core.run_scan
        self.pending = {}          # (resource_index, key) -> new value
        self.sort = (None, False)
        self.busy = False
        self._build()
        self.after(100, self._poll)

    # ------------------------------------------------------------------ UI
    def _build(self):
        style = ttk.Style(self)
        if IS_WIN and "vista" in style.theme_names():
            style.theme_use("vista")
        elif not IS_MAC and "clam" in style.theme_names():
            style.theme_use("clam")  # Linux default theme is very dated; macOS keeps native "aqua"
        bold = tkfont.nametofont("TkDefaultFont").copy()
        bold.configure(weight="bold")
        self._bold = bold
        style.configure("Big.TButton", font=bold, padding=6)

        menubar = tk.Menu(self)
        cred_menu = tk.Menu(menubar, tearoff=0)
        cred_menu.add_command(label="Update credentials…", command=self.open_credentials_dialog)
        cred_menu.add_command(label="Clear pasted credentials", command=self.clear_pasted_credentials)
        menubar.add_cascade(label="Credentials", menu=cred_menu)
        self.config(menu=menubar)
        self.pasted_env = set()

        # --- top: connection
        top = ttk.Frame(self, padding=(8, 8, 8, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Profile:").pack(side="left")
        try:
            profiles = ["(default)"] + core.boto3.Session().available_profiles
        except Exception:
            profiles = ["(default)"]
        self.profile = ttk.Combobox(top, values=profiles, width=24)
        self.profile.set(profiles[0])
        self.profile.pack(side="left", padx=(4, 12))
        ttk.Label(top, text="Start region:").pack(side="left")
        self.start_region = ttk.Entry(top, width=18)
        self.start_region.insert(0, os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "")
        self.start_region.pack(side="left", padx=(4, 12))
        self.connect_btn = ttk.Button(top, text="Connect", command=self.connect)
        self.connect_btn.pack(side="left")
        ttk.Button(top, text="Credentials…", command=self.open_credentials_dialog).pack(side="left", padx=(6, 0))
        self.acct_lbl = ttk.Label(top, text="Not connected", foreground="#a00")
        self.acct_lbl.pack(side="left", padx=12)

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=4)
        left = ttk.Frame(paned, width=330)
        right = ttk.Frame(paned)
        paned.add(left, weight=0)
        paned.add(right, weight=1)

        # --- left: regions
        rf = ttk.LabelFrame(left, text=" 1. Regions to scan ", padding=6)
        rf.pack(fill="x")
        bar = ttk.Frame(rf)
        bar.pack(fill="x")
        ttk.Button(bar, text="All", width=6, command=lambda: self.regions.set_all(True)).pack(side="left")
        ttk.Button(bar, text="None", width=6, command=lambda: self.regions.set_all(False)).pack(side="left", padx=4)
        self.regions = CheckList(rf, height=120)
        self.regions.pack(fill="x", pady=(4, 0))
        ttk.Label(self.regions.inner, text="Connect to load regions", foreground="#777").grid()

        # --- left: tag keys
        kf = ttk.LabelFrame(left, text=" 2. Required tag keys ", padding=6)
        kf.pack(fill="x", pady=6)
        ttk.Label(kf, text="Flag resources missing ANY of these (case-sensitive).\n"
                           "Type a key or pick one found in your account (after a scan):",
                  foreground="#555", justify="left").pack(anchor="w")
        self.keys_lb = tk.Listbox(kf, height=4, selectmode="extended", exportselection=False)
        self.keys_lb.pack(fill="x", pady=4)
        self.keys_lb.insert("end", "Program")
        row = ttk.Frame(kf)
        row.pack(fill="x")
        # Type any key, or pick one from the dropdown (filled with every tag key found by the last scan).
        self.key_entry = ttk.Combobox(row, values=[])
        self.key_entry.pack(side="left", fill="x", expand=True)
        self.key_entry.bind("<<ComboboxSelected>>", lambda e: self.add_key())
        self.key_entry.bind("<Return>", lambda e: self.add_key())
        ttk.Button(row, text="Add", width=6, command=self.add_key).pack(side="left", padx=4)
        ttk.Button(row, text="Remove", width=8, command=self.remove_key).pack(side="left")

        # --- left: resource types
        sf = ttk.LabelFrame(left, text=" 3. Resource types ", padding=6)
        sf.pack(fill="both", expand=True)
        bar = ttk.Frame(sf)
        bar.pack(fill="x")
        ttk.Button(bar, text="Main only", command=lambda: self.types.main_only()).pack(side="left")
        ttk.Button(bar, text="All", width=4, command=lambda: self.types.set_all(True)).pack(side="left", padx=2)
        ttk.Button(bar, text="None", width=5, command=lambda: self.types.set_all(False)).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="New type\u2026", command=self.new_custom).pack(side="left")
        ttk.Button(bar, text="Edit\u2026", width=6, command=self.edit_custom).pack(side="left", padx=2)
        ttk.Button(bar, text="Delete", width=6, command=self.delete_custom).pack(side="left")
        self.types = TypeTree(sf, height=8)
        self.types.pack(fill="both", expand=True, pady=4)
        self.types.tv.bind("<Double-1>", lambda e: self.edit_custom(quiet=True))
        self.use_api = tk.BooleanVar(value=False)
        ttk.Checkbutton(sf, text="Also use Tagging API catch-all (every tagged thing of ANY type, very granular)",
                        variable=self.use_api).pack(anchor="w")
        self.custom_types = []
        try:
            self.custom_types = core.load_custom_types()
        except (ValueError, OSError) as e:
            messagebox.showerror("Custom types", "Couldn't read %s:\n%s" % (core.DEFAULT_TYPES_FILE, e))
        core.register_custom_types(self.custom_types)
        self.types.load(core.COLLECTORS)

        self.scan_btn = ttk.Button(left, text="Scan", style="Big.TButton", command=self.scan, state="disabled")
        self.scan_btn.pack(fill="x", pady=(8, 4))
        self.progress = ttk.Progressbar(left, mode="indeterminate")
        self.progress.pack(fill="x")

        # --- right: filter bar
        fb = ttk.Frame(right)
        fb.pack(fill="x")
        ttk.Label(fb, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *a: self.refresh())
        ttk.Entry(fb, textvariable=self.filter_var, width=30).pack(side="left", padx=4)
        self.only_bad = tk.BooleanVar(value=True)
        ttk.Checkbutton(fb, text="Only show non-compliant", variable=self.only_bad, command=self.refresh).pack(side="left", padx=8)
        self.hide_k8s = tk.BooleanVar(value=True)
        ttk.Checkbutton(fb, text="Hide EKS-managed (nodes, pods' volumes/ENIs/LBs)", variable=self.hide_k8s,
                        command=self.refresh).pack(side="left", padx=(0, 8))
        self.type_filter = {}  # "service:type" -> shown?
        self.types_btn = ttk.Button(fb, text="Types: all ▾", command=self.open_type_filter)
        self.types_btn.pack(side="left")
        self.count_lbl = ttk.Label(right, text="", foreground="#444")
        self.count_lbl.pack(anchor="w", pady=(3, 0))

        # --- right: table
        tf = ttk.Frame(right)
        tf.pack(fill="both", expand=True, pady=4)
        self.tree = ttk.Treeview(tf, show="headings", selectmode="extended")
        ys = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)
        # Explicit dark text: in macOS dark mode the default text is white, unreadable on pale rows.
        self.tree.tag_configure("bad", background="#fde8e8", foreground="#111")
        self.tree.tag_configure("pending", background="#fff6cc", foreground="#111")
        self.tree.tag_configure("ok", background="#e9f7ec", foreground="#111")
        self.tree.bind("<Double-1>", self.on_double)
        self.tree.bind("<%s-a>" % MOD, lambda e: (self.tree.selection_set(self.tree.get_children()), "break")[1])
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._update_counts())
        self._set_columns()

        # --- right: edit bar
        eb = ttk.LabelFrame(right, text=" 4. Set tag values ", padding=6)
        eb.pack(fill="x")
        ttk.Label(eb, text="Key").pack(side="left")
        self.edit_key = ttk.Combobox(eb, width=16, state="readonly")
        self.edit_key.pack(side="left", padx=4)
        ttk.Label(eb, text="Value").pack(side="left")
        self.edit_val = ttk.Entry(eb, width=26)
        self.edit_val.pack(side="left", padx=4)
        self.edit_val.bind("<Return>", lambda e: self.set_value(selected=True))
        self.only_missing = tk.BooleanVar(value=True)
        ttk.Checkbutton(eb, text="only where missing", variable=self.only_missing).pack(side="left", padx=4)
        ttk.Button(eb, text="Set on selected", command=lambda: self.set_value(selected=True)).pack(side="left", padx=2)
        ttk.Button(eb, text="Set on all shown", command=lambda: self.set_value(selected=False)).pack(side="left", padx=2)
        ttk.Button(eb, text="Clear pending (selected)", command=self.clear_pending).pack(side="left", padx=2)
        ttk.Label(right, text="Tip: double-click a tag cell to edit one resource. Ctrl+A selects all shown rows. "
                              "Yellow = pending change, red = non-compliant, green = compliant.",
                  foreground="#666").pack(anchor="w", pady=(2, 0))

        # --- right: action bar
        ab = ttk.Frame(right)
        ab.pack(fill="x", pady=4)
        self.dry_run = tk.BooleanVar(value=False)
        self.apply_btn = ttk.Button(ab, text="Apply 0 pending changes", style="Big.TButton", command=self.apply, state="disabled")
        self.apply_btn.pack(side="left")
        ttk.Checkbutton(ab, text="Dry run", variable=self.dry_run).pack(side="left", padx=8)
        ttk.Button(ab, text="Export CSV...", command=self.export).pack(side="right")

        # --- log
        lf = ttk.LabelFrame(self, text=" Log ", padding=4)
        lf.pack(fill="x", padx=8, pady=(0, 8))
        self.log_txt = tk.Text(lf, height=9, wrap="none", font=MONO, state="disabled")
        lsb = ttk.Scrollbar(lf, orient="vertical", command=self.log_txt.yview)
        self.log_txt.configure(yscrollcommand=lsb.set)
        self.log_txt.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")
        self._refresh_key_combo()

    # ------------------------------------------------------------- helpers
    def keys(self):
        return list(self.keys_lb.get(0, "end"))

    def log(self, msg):
        self.log_txt.configure(state="normal")
        self.log_txt.insert("end", msg + "\n")
        self.log_txt.see("end")
        self.log_txt.configure(state="disabled")

    def log_bg(self, msg):
        self.q.put(("log", msg))

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item[0] == "log":
                    self.log(item[1])
                elif item[0] == "done":
                    self._set_busy(False)
                    item[1](item[2])
                elif item[0] == "error":
                    self._set_busy(False)
                    self.log("ERROR: " + item[1])
                    if item[2]:
                        item[2](item[1])
                    messagebox.showerror("Error", item[1])
        except queue.Empty:
            pass
        except Exception as e:  # noqa: BLE001 - never let the poll loop die
            self.log("INTERNAL ERROR: %s: %s" % (type(e).__name__, e))
        finally:
            self.after(100, self._poll)

    def _bg(self, fn, on_done, on_error=None):
        self._set_busy(True)

        def run():
            try:
                self.q.put(("done", on_done, fn()))
            except SystemExit as e:
                self.q.put(("error", str(e), on_error))
            except Exception as e:  # noqa: BLE001
                self.q.put(("error", "%s: %s" % (type(e).__name__, e), on_error))
        threading.Thread(target=run, daemon=True).start()

    def _set_busy(self, b):
        self.busy = b
        st = "disabled" if b else "normal"
        self.connect_btn.configure(state=st)
        self.scan_btn.configure(state="disabled" if b or not self.ctx else "normal")
        self.apply_btn.configure(state="disabled" if b or not self._pending_items() else "normal")
        if b:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)

    def _refresh_key_combo(self):
        ks = self.keys()
        self.edit_key.configure(values=ks)
        if self.edit_key.get() not in ks:
            self.edit_key.set(ks[0] if ks else "")

    # -------------------------------------------------------------- keys
    def add_key(self):
        k = self.key_entry.get().strip()
        if not k:
            return
        if len(k) > 128 or k.lower().startswith("aws:"):
            messagebox.showwarning("Invalid key", "Tag keys are max 128 chars and can't start with 'aws:'.")
            return
        if k in self.keys():
            return
        self.keys_lb.insert("end", k)
        self.key_entry.delete(0, "end")
        self._keys_changed()

    def remove_key(self):
        for i in reversed(self.keys_lb.curselection()):
            self.keys_lb.delete(i)
        self._keys_changed()

    def _keys_changed(self):
        self._refresh_key_combo()
        self._set_columns()
        self.refresh()

    # -------------------------------------------------------- credentials
    def apply_env_credentials(self, env):
        """Write pasted vars into os.environ (memory only). Returns a masked summary."""
        for k, v in env.items():
            os.environ[k] = v
            self.pasted_env.add(k)
        if "AWS_ACCESS_KEY_ID" in env:
            # A named profile makes boto3 ignore env keys, so switch to the default chain.
            if self.profile.get() not in ("", "(default)"):
                self.log("Switched profile to (default) so the pasted keys are used (was %s)." % self.profile.get())
            self.profile.set("(default)")
        elif "AWS_PROFILE" in env:
            self.profile.set(env["AWS_PROFILE"])
        region = env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
        if region:
            self.start_region.delete(0, "end")
            self.start_region.insert(0, region)
        summary = ", ".join(mask(k, v) for k, v in env.items())
        self.log("Credentials applied (in memory only, not saved): " + summary)
        return summary

    def clear_pasted_credentials(self):
        if not self.pasted_env:
            messagebox.showinfo("Nothing to clear", "No credentials have been pasted in this session.")
            return
        for k in self.pasted_env:
            os.environ.pop(k, None)
        self.log("Cleared pasted variables: " + ", ".join(sorted(self.pasted_env)) + ". Click Connect to reconnect.")
        self.pasted_env.clear()
        self.ctx = None
        self.acct_lbl.configure(text="Not connected", foreground="#a00")
        self.scan_btn.configure(state="disabled")

    def open_credentials_dialog(self):
        win = tk.Toplevel(self)
        win.title("Update credentials")
        win.geometry("720x500+%d+%d" % (self.winfo_rootx() + 80, self.winfo_rooty() + 60))
        win.transient(self)
        ttk.Label(win, padding=(8, 8, 8, 0), justify="left", wraplength=690, text=(
            "Paste the credential lines you'd run in a shell, e.g. from the AWS access portal's "
            "\"Command line or programmatic access\" page, then Apply. They go into this app's environment "
            "(memory only, never saved), so the next Connect uses them - no restart.\n"
            "Accepts:  export KEY=VALUE  |  set KEY=VALUE  |  $env:KEY=\"VALUE\"  |  KEY=VALUE   (# comments ignored)\n"
            "Typical keys: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION, "
            "AWS_PROFILE, AWS_CA_BUNDLE.")).pack(fill="x")
        wrap = ttk.Frame(win, padding=8)
        wrap.pack(fill="both", expand=True)
        txt = tk.Text(wrap, wrap="none", font=MONO_BIG, undo=True, height=10,
                      background="#111", foreground="#ddd", insertbackground="#ddd")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=vs.set)
        txt.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        txt.focus_set()
        status = ttk.Label(win, padding=(8, 0), foreground="#555", justify="left", wraplength=690, text="")
        status.pack(fill="x")
        btns = ttk.Frame(win, padding=8)
        btns.pack(fill="x")

        def apply(verify):
            try:
                env = parse_env_assignments(txt.get("1.0", "end-1c"))
            except ValueError as e:
                messagebox.showerror("Can't parse", str(e), parent=win)
                return
            if not env:
                messagebox.showinfo("Nothing to apply", "No KEY=VALUE assignments found.", parent=win)
                return
            if "AWS_ACCESS_KEY_ID" in env and "AWS_SECRET_ACCESS_KEY" not in env and not os.environ.get("AWS_SECRET_ACCESS_KEY"):
                messagebox.showwarning("Incomplete", "AWS_ACCESS_KEY_ID needs AWS_SECRET_ACCESS_KEY too.", parent=win)
                return
            if "AWS_ACCESS_KEY_ID" in env and env["AWS_ACCESS_KEY_ID"].startswith("ASIA") \
                    and "AWS_SESSION_TOKEN" not in env:
                messagebox.showwarning("Missing session token", "Keys starting with ASIA are temporary and also need "
                                       "AWS_SESSION_TOKEN.", parent=win)
                return
            if "AWS_ACCESS_KEY_ID" in env and env["AWS_ACCESS_KEY_ID"].startswith("AKIA") \
                    and "AWS_SESSION_TOKEN" not in env:
                os.environ.pop("AWS_SESSION_TOKEN", None)  # don't pair long-term keys with a stale token
            applied = "✓ applied: " + self.apply_env_credentials(env)
            status.configure(text=applied)
            txt.delete("1.0", "end")  # don't leave secrets sitting in the widget
            if verify:
                status.configure(text=applied + "\n⏳ verifying (sts get-caller-identity)...")
                self.connect(on_result=lambda ok, msg: win.winfo_exists() and status.configure(
                    text=applied + "\n" + ("✓ verified: " if ok else "⚠ verify failed: ") + msg))

        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")
        ttk.Button(btns, text="✔ Apply & verify", style="Big.TButton", command=lambda: apply(True)).pack(side="right", padx=4)
        ttk.Button(btns, text="Apply", command=lambda: apply(False)).pack(side="right")
        self._cred_win = win

    # ------------------------------------------------------------ connect
    def connect(self, on_result=None):
        prof = self.profile.get().strip()
        prof = None if prof in ("", "(default)") else prof
        region = self.start_region.get().strip() or None

        def work():
            ctx = core.Ctx(prof, region)
            return ctx, ctx.enabled_regions()

        def done(result):
            self.ctx, regions = result
            self.acct_lbl.configure(text="Account %s  |  %s  |  %s" % (self.ctx.account, self.ctx.partition, self.ctx.caller_arn),
                                    foreground="#070")
            if not self.start_region.get().strip():
                self.start_region.insert(0, self.ctx.start_region)
            self.regions.set_items(regions, True)
            self.scan_btn.configure(state="normal")
            self.log("Connected to %s as %s; %d enabled regions." % (self.ctx.account, self.ctx.caller_arn, len(regions)))
            if self.resources:
                self.resources, self.pending = [], {}
                self.refresh()
            if on_result:
                on_result(True, "account %s as %s" % (self.ctx.account, self.ctx.caller_arn))

        def failed(msg):
            self.ctx = None
            self.acct_lbl.configure(text="Not connected", foreground="#a00")
            self.scan_btn.configure(state="disabled")
            if on_result:
                on_result(False, msg)
        self.log("Connecting...")
        self._bg(work, done, failed)

    # --------------------------------------------------------------- scan
    def scan(self):
        regions = self.regions.selected()
        if not regions:
            messagebox.showwarning("No regions", "Tick at least one region.")
            return
        if not self.keys():
            messagebox.showwarning("No tag keys", "Add at least one required tag key.")
            return
        if self.pending and not messagebox.askyesno("Discard pending?", "A new scan discards %d pending changes. Continue?" % len(self.pending)):
            return
        types = self.types.selected()
        if not types and not self.use_api.get():
            messagebox.showwarning("Nothing to scan", "Tick at least one resource type or the Tagging API option.")
            return
        include = set() if self.types.all_selected() else (set(types) or {"__none__"})
        use_api = self.use_api.get()  # read Tk vars on the main thread only
        self.ctx.workers = 8
        self.log("Scanning %d regions: %s" % (len(regions), ", ".join(regions)))

        def work():
            return core.run_scan(self.ctx, regions, include, set(), use_api, progress=self.log_bg)

        def done(resources):
            self.resources = resources
            self.pending = {}
            self.refresh()
            bad = sum(1 for r in resources if self._noncompliant(r) and not r.get("k8s"))
            self.log("Scan complete: %d resources, %d non-compliant for %s." % (len(resources), bad, ", ".join(self.keys())))
            k8s = Counter(r["k8s"] for r in resources if r.get("k8s"))
            if k8s:
                self.log("Hidden as EKS/Kubernetes-managed (untick 'Hide EKS-managed' to see them): " +
                         ", ".join("%s x%d" % kv for kv in k8s.most_common()))
            # Suggest keys people choose; skip ones AWS/Kubernetes controllers stamp automatically.
            system = ("aws:", "eks:", "karpenter.", "kubernetes.io", "k8s.", "CSIVolume")
            found = Counter(k for r in resources if not r.get("k8s") for k in r["tags"]
                            if not k.startswith(system) and "k8s.aws/" not in k and "kubernetes.io/" not in k
                            and ".k8s.amazonaws.com/" not in k)
            self.key_entry.configure(values=[k for k, _ in found.most_common()])
            if found:
                self.log("%d distinct tag keys found; pick any from the dropdown in section 2 to require it. Most common: %s" % (
                    len(found), ", ".join("%s (%d)" % kv for kv in found.most_common(8))))
            api_only = Counter("%s:%s" % (r["service"], r["type"]) for r in resources if r["source"] == "tagging-api")
            if api_only:
                self.log("Types found only via the Tagging API (never-tagged ones of these are invisible to it; "
                         "add a custom type to catch them): " + ", ".join("%s x%d" % kv for kv in api_only.most_common(12)))
            blocked, errs = core.summarize_errors(self.ctx)
            if blocked:
                self.log("Blocked regions (almost every call denied, likely an SCP or not opted in), nothing scanned: " + ", ".join(blocked))
            if errs:
                self.log("%d collector errors (not fatal): %s" % (len(errs), ", ".join("%s x%d" % kv for kv in Counter(e[2] for e in errs).most_common(4))))
                for e in errs[:15]:
                    self.log("   %s @ %s: %s" % (e[0], e[1], e[2]))
        self._bg(work, done)

    # -------------------------------------------------------- custom types
    def new_custom(self):
        CustomTypeDialog(self)

    def edit_custom(self, quiet=False):
        n = self.types.focused_name()
        spec = next((t for t in self.custom_types if t["name"] == n), None)
        if spec:
            CustomTypeDialog(self, dict(spec))
        elif not quiet:
            messagebox.showinfo("Edit", "Select one of your custom types (under \u2605 custom) to edit it. Built-in types can't be edited.")

    def delete_custom(self):
        n = self.types.focused_name()
        if not any(t["name"] == n for t in self.custom_types):
            messagebox.showinfo("Delete", "Select one of your custom types (under \u2605 custom) to delete it.")
            return
        if messagebox.askyesno("Delete type", "Delete custom type '%s'?" % n):
            self.custom_types = [t for t in self.custom_types if t["name"] != n]
            self._persist_custom("Deleted custom type %s" % n)

    def save_custom(self, spec, old_name=None):
        self.custom_types = [t for t in self.custom_types if t["name"] not in (old_name, spec["name"])]
        self.custom_types.append(spec)
        self.custom_types.sort(key=lambda t: t["name"])
        self._persist_custom("Saved custom type %s: %s" % (spec["name"], spec["command"]))

    def _persist_custom(self, msg):
        try:
            path = core.save_custom_types(self.custom_types)
        except OSError as e:
            messagebox.showerror("Save failed", "Couldn't write %s:\n%s" % (core.DEFAULT_TYPES_FILE, e))
            return
        core.register_custom_types(self.custom_types)
        self.types.load(core.COLLECTORS)
        self.log("%s  (%s)" % (msg, path))

    # -------------------------------------------------------------- table
    def _set_columns(self):
        cols = ["type", "region", "name", "id"] + ["k:" + k for k in self.keys()]
        self.tree.configure(columns=cols)
        widths = {"type": 190, "region": 105, "name": 220, "id": 220}
        for c in cols:
            label = c[2:] if c.startswith("k:") else c.capitalize()
            self.tree.heading(c, text=label, command=lambda c=c: self._sort_by(c))
            self.tree.column(c, width=widths.get(c, 150), stretch=c.startswith("k:") or c == "name", anchor="w")

    def _sort_by(self, col):
        self.sort = (col, not self.sort[1] if self.sort[0] == col else False)
        self.refresh()

    def _cell(self, idx, key):
        if (idx, key) in self.pending:
            return ARROW + self.pending[(idx, key)]
        r = self.resources[idx]
        reason = core.evaluate(r["tags"], key)
        if reason is None:
            return r["tags"][key]
        if reason == "missing":
            return MISSING
        if reason == "empty-value":
            return EMPTY
        near = [k for k in r["tags"] if k.strip().lower() == key.lower()]
        return "✗ " + ", ".join("%s=%s" % (k, r["tags"][k]) for k in near)

    def _noncompliant(self, r):
        return any(core.evaluate(r["tags"], k) for k in self.keys())

    @staticmethod
    def _tkey(r):
        return "%s:%s" % (r["service"], r["type"])

    def _in_scope(self, r):
        """Not hidden by the Kubernetes-workload toggle (type filter is separate)."""
        return not (self.hide_k8s.get() and r.get("k8s"))

    def open_type_filter(self):
        if getattr(self, "_tf_win", None) is not None and self._tf_win.winfo_exists():
            self._tf_win.lift()
            return
        if not self.resources:
            messagebox.showinfo("No results yet", "Run a scan first; this filters the results by resource type.")
            return
        win = tk.Toplevel(self)
        self._tf_win = win
        win.title("Show resource types")
        win.transient(self)
        win.geometry("+%d+%d" % (self.types_btn.winfo_rootx(), self.types_btn.winfo_rooty() + self.types_btn.winfo_height() + 4))
        total, bad = Counter(), Counter()
        for r in self.resources:
            if self._in_scope(r):
                total[self._tkey(r)] += 1
                if self._noncompliant(r):
                    bad[self._tkey(r)] += 1
        names = sorted(total)
        labels = {t: "%s   (%d non-compliant / %d)" % (t, bad[t], total[t]) for t in names}
        ttk.Label(win, text="Tick the resource types to show in the list:", padding=(8, 8, 8, 2)).pack(anchor="w")
        bar = ttk.Frame(win, padding=(8, 0))
        bar.pack(fill="x")
        cl = CheckList(win, height=min(420, 26 * len(names) + 10))

        def set_all(v, only_bad=False):
            for t, var in cl.vars.items():
                var.set(bool(bad[t]) if only_bad else v)
        ttk.Button(bar, text="All", width=5, command=lambda: set_all(True)).pack(side="left")
        ttk.Button(bar, text="None", width=5, command=lambda: set_all(False)).pack(side="left", padx=2)
        ttk.Button(bar, text="Only types with gaps", command=lambda: set_all(None, True)).pack(side="left", padx=2)
        cl.pack(fill="both", expand=True, padx=8, pady=6)
        cl.set_items(names, lambda t: self.type_filter.get(t, True), cols=1, labels=labels)

        def changed(*_):
            for t, var in cl.vars.items():
                self.type_filter[t] = var.get()
            self.refresh()
        for var in cl.vars.values():
            var.trace_add("write", changed)
        ttk.Button(win, text="Close", command=win.destroy).pack(anchor="e", padx=8, pady=(0, 8))

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        keys = self.keys()
        needle = self.filter_var.get().strip().lower()
        rows = []
        self._k8s_hidden = 0
        present = set()
        for i, r in enumerate(self.resources):
            if not self._in_scope(r):
                self._k8s_hidden += 1
                continue
            present.add(self._tkey(r))
            if not self.type_filter.get(self._tkey(r), True):
                continue
            bad = self._noncompliant(r)
            has_pending = any((i, k) in self.pending for k in keys)
            if self.only_bad.get() and not bad and not has_pending:
                continue
            vals = ["%s:%s" % (r["service"], r["type"]), r["region"], r["name"], r["id"]] + [self._cell(i, k) for k in keys]
            if needle and not any(needle in str(v).lower() for v in vals + [r["arn"]]):
                continue
            tag = "pending" if has_pending else ("bad" if bad else "ok")
            rows.append((i, vals, tag))
        col, rev = self.sort
        if col:
            ci = list(self.tree["columns"]).index(col) if col in self.tree["columns"] else 0
            rows.sort(key=lambda x: str(x[1][ci]).lower(), reverse=rev)
        for i, vals, tag in rows:
            self.tree.insert("", "end", iid=str(i), values=vals, tags=(tag,))
        self._shown = len(rows)
        off = [t for t in present if not self.type_filter.get(t, True)]
        self.types_btn.configure(text=("Types: %d of %d ▾" % (len(present) - len(off), len(present))) if off else "Types: all ▾")
        self._update_counts()

    def _pending_items(self):
        ks = set(self.keys())
        return {k: v for k, v in self.pending.items() if k[1] in ks}

    def _update_counts(self):
        scope = [r for r in self.resources if self._in_scope(r)]
        bad = sum(1 for r in scope if self._noncompliant(r))
        p = self._pending_items()
        k8s = getattr(self, "_k8s_hidden", 0)
        self.count_lbl.configure(text="%d shown  |  %d selected  |  %d of %d non-compliant  |  %d pending%s" % (
            getattr(self, "_shown", 0), len(self.tree.selection()), bad, len(scope), len(p),
            ("  |  %d EKS-managed hidden" % k8s) if k8s else ""))
        n_res = len({i for i, _ in p})
        self.apply_btn.configure(text="Apply %d pending changes (%d resources)" % (len(p), n_res),
                                 state="normal" if p and not self.busy else "disabled")

    # -------------------------------------------------------------- edits
    def _check_value(self, v):
        if not core.valid_value(v):
            messagebox.showwarning("Invalid value", "Max 256 chars; letters, numbers, spaces and _ . : / = + - @ only.")
            return False
        return True

    def set_value(self, selected=True):
        key, val = self.edit_key.get(), self.edit_val.get().strip()
        if not key:
            messagebox.showwarning("No key", "Add a required tag key first.")
            return
        if not val or not self._check_value(val):
            return
        targets = self.tree.selection() if selected else self.tree.get_children()
        if not targets:
            messagebox.showinfo("Nothing selected", "Select rows in the table first (Ctrl+A for all shown).")
            return
        n = 0
        for iid in targets:
            i = int(iid)
            if self.only_missing.get() and core.evaluate(self.resources[i]["tags"], key) is None:
                continue
            self.pending[(i, key)] = val
            n += 1
        self.log("Pending: %s=%s on %d resources%s." % (key, val, n, " (skipped ones that already have it)" if n < len(targets) else ""))
        sel = self.tree.selection()
        self.refresh()
        self.tree.selection_set([s for s in sel if self.tree.exists(s)])

    def clear_pending(self):
        sel = self.tree.selection()
        for iid in sel:
            for k in self.keys():
                self.pending.pop((int(iid), k), None)
        self.refresh()
        self.tree.selection_set([s for s in sel if self.tree.exists(s)])

    def on_double(self, event):
        iid, col = self.tree.identify_row(event.y), self.tree.identify_column(event.x)
        if not iid or not col:
            return
        cname = self.tree["columns"][int(col[1:]) - 1]
        if not cname.startswith("k:"):
            return
        key, i = cname[2:], int(iid)
        r = self.resources[i]
        current = self.pending.get((i, key), r["tags"].get(key, ""))
        v = simpledialog.askstring("Set %s" % key, "%s:%s  %s\n%s\n\nValue for '%s' (blank = clear pending):" % (
            r["service"], r["type"], r["name"] or r["id"], r["arn"], key), initialvalue=current, parent=self)
        if v is None:
            return
        v = v.strip()
        if not v:
            self.pending.pop((i, key), None)
        elif self._check_value(v):
            if v == r["tags"].get(key):
                self.pending.pop((i, key), None)
            else:
                self.pending[(i, key)] = v
        self.refresh()
        if self.tree.exists(iid):
            self.tree.selection_set(iid)
            self.tree.see(iid)

    # -------------------------------------------------------------- apply
    def apply(self):
        p = self._pending_items()
        if not p:
            return
        by_key = defaultdict(list)
        for (i, k), v in p.items():
            by_key[k].append((self.resources[i], v))
        summary = "\n".join("  %s = %s  x%d" % (k, v, n) for (k, v), n in Counter((k, v) for (_, k), v in p.items()).most_common(15))
        dry = self.dry_run.get()
        if not messagebox.askyesno("Confirm" + (" (DRY RUN)" if dry else ""),
                                   "%s %d tag changes on %d resources in account %s?\n\n%s\n\nOnly these keys are added/overwritten; other tags are untouched." % (
                                       "Simulate" if dry else "Apply", len(p), len({i for i, _ in p}), self.ctx.account, summary)):
            return
        self.log("%s %d tag changes..." % ("DRY RUN:" if dry else "Applying", len(p)))

        def work():
            out = []
            for k, plan in by_key.items():
                out.extend((k, r) for r in core.apply_tags(self.ctx, plan, k, dry, log=self.log_bg))
            return out

        def done(results):
            arn_idx = {r["arn"]: i for i, r in enumerate(self.resources)}
            c = Counter(r["status"] for _, r in results)
            if not dry:
                for k, r in results:
                    if r["status"] == "tagged":
                        i = arn_idx[r["arn"]]
                        self.resources[i]["tags"][k] = r[k]
                        self.pending.pop((i, k), None)
            self.refresh()
            self.log("Done: %s" % ", ".join("%s=%d" % kv for kv in c.items()))
            stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            path = os.path.abspath("tag-apply-results_%s_%s.csv" % (self.ctx.account, stamp))
            try:
                fields = ["status", "message", "tag_key", "tag_value", "service", "type", "region", "name", "id", "arn"]
                core.write_csv(path, [dict(r, tag_key=k, tag_value=r[k]) for k, r in results], fields)
                self.log("Results saved: %s" % path)
            except OSError as e:
                self.log("Could not save results CSV: %s" % e)
            if c.get("failed"):
                messagebox.showwarning("Some failed", "%d changes failed (still shown as pending). See the log / results CSV." % c["failed"])
            else:
                messagebox.showinfo("Done", "%s %d tag changes." % ("Simulated" if dry else "Applied", c.get("tagged", 0) + c.get("dry-run", 0)))
        self._bg(work, done)

    # ------------------------------------------------------------- export
    def export(self):
        if not self.resources:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        acct = self.ctx.account if self.ctx else "aws"
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile="tag-audit_%s_%s.csv" % (acct, _dt.datetime.now().strftime("%Y%m%d-%H%M%S")))
        if not path:
            return
        keys = self.keys()
        only_shown = set(self.tree.get_children())
        rows = []
        for i, r in enumerate(self.resources):
            if str(i) not in only_shown:
                continue
            row = {"compliant": "no" if self._noncompliant(r) else "yes", "service": r["service"], "type": r["type"],
                   "region": r["region"], "name": r["name"], "id": r["id"], "arn": r["arn"], "source": r["source"],
                   "k8s_workload": r.get("k8s", ""), "tags_json": core.json.dumps(r["tags"], sort_keys=True)}
            for k in keys:
                row[k] = r["tags"].get(k, "")
                row[k + "_status"] = core.evaluate(r["tags"], k) or "ok"
                row[k + "_pending"] = self.pending.get((i, k), "")
            rows.append(row)
        fields = ["compliant", "service", "type", "region", "name", "id"] + \
                 [f for k in keys for f in (k, k + "_status", k + "_pending")] + ["arn", "source", "k8s_workload", "tags_json"]
        core.write_csv(path, rows, fields)
        self.log("Exported %d rows (what's currently shown) to %s" % (len(rows), path))


def main():
    core._safe_console()
    App().mainloop()


if __name__ == "__main__":
    main()
