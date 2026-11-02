"""Desktop interface for the offline phishing link detector."""

import os
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from threading import Thread

from .analyzer import AnalysisResult, analyze_url
from .gemini import GeminiApiError, GeminiExplainer
from .reputation import OpenPhishFeedChecker, ReputationFeedError
from .self_test import run_safe_self_test


class DetectorWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.feed_checker = OpenPhishFeedChecker()
        self.gemini = GeminiExplainer(
            os.environ.get("LINKSHIELD_GEMINI_API_KEY")
        )
        self.current_result: AnalysisResult | None = None
        self.result_version = 0
        self.details_canvas: tk.Canvas | None = None
        self.copy_status: ttk.Label | None = None
        self.ai_status: ttk.Label | None = None
        self.ai_button: ttk.Button | None = None
        root.title("LinkShield | Phishing Link Detector")
        root.geometry("820x760")
        root.minsize(680, 640)
        root.configure(bg="#f4f7fb")

        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f4f7fb")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure(
            "TLabel",
            background="#f4f7fb",
            foreground="#17233b",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 27, "bold"),
            foreground="#12213a",
        )
        style.configure(
            "Subtitle.TLabel",
            font=("Segoe UI", 10),
            foreground="#64748b",
        )
        style.configure(
            "CardTitle.TLabel",
            background="#ffffff",
            font=("Segoe UI", 11, "bold"),
            foreground="#263651",
        )
        style.configure(
            "Body.TLabel",
            background="#ffffff",
            foreground="#43516a",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(18, 11),
        )
        style.map(
            "Primary.TButton",
            background=[("!disabled", "#2457e6"), ("active", "#1744c1")],
            foreground=[("!disabled", "#ffffff")],
        )
        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(12, 11),
        )
        style.configure("TEntry", padding=11, font=("Segoe UI", 11))

        main = ttk.Frame(root, padding=(36, 30))
        main.pack(fill="both", expand=True)

        header = ttk.Frame(main)
        header.pack(fill="x")
        ttk.Label(header, text="LinkShield", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="A clearer first look at a link before you open it.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        input_card = ttk.Frame(main, style="Card.TFrame", padding=(22, 20))
        input_card.pack(fill="x", pady=(20, 0))
        ttk.Label(input_card, text="Paste a web link", style="CardTitle.TLabel").pack(anchor="w")
        input_row = ttk.Frame(input_card, style="Card.TFrame")
        input_row.pack(fill="x", pady=(10, 0))
        self.url_entry = ttk.Entry(input_row)
        self.url_entry.pack(side="left", fill="x", expand=True)
        self.url_entry.bind("<Return>", lambda _event: self.check_link())
        ttk.Button(
            input_row,
            text="Paste",
            style="Secondary.TButton",
            command=self.paste_link,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            input_row,
            text="Clear",
            style="Secondary.TButton",
            command=self.clear_input,
        ).pack(side="left", padx=(8, 0))
        self.check_button = ttk.Button(
            input_row,
            text="Check link",
            style="Primary.TButton",
            command=self.check_link,
        )
        self.check_button.pack(side="left", padx=(10, 0))
        ttk.Label(
            input_card,
            text=(
                "Local URL checks never open the link. Optional online checks send "
                "limited data only after you confirm."
            ),
            style="Body.TLabel",
            wraplength=700,
        ).pack(anchor="w", pady=(11, 0))
        input_actions = ttk.Frame(input_card, style="Card.TFrame")
        input_actions.pack(anchor="w", pady=(12, 0))
        ttk.Button(
            input_actions,
            text="Run safe self-test",
            style="Secondary.TButton",
            command=self.show_safe_self_test,
        ).pack(side="left")
        ttk.Button(
            input_actions,
            text="Set Gemini API key",
            style="Secondary.TButton",
            command=self.configure_gemini_key,
        ).pack(side="left", padx=(8, 0))

        self.error_label = ttk.Label(main, text="", foreground="#b42318")
        self.error_label.pack(anchor="w", pady=(7, 0))

        self.results = ttk.Frame(main, style="Card.TFrame", padding=(24, 22))
        self.results.pack(fill="both", expand=True, pady=(15, 0))
        root.bind_all("<MouseWheel>", self._on_mousewheel, add="+")
        root.bind_all("<Button-4>", self._on_mousewheel, add="+")
        root.bind_all("<Button-5>", self._on_mousewheel, add="+")
        self.placeholder = ttk.Label(
            self.results,
            text="Your results will appear here.\n\nPaste a link above and select Check link to begin.",
            style="Body.TLabel",
            justify="left",
        )
        self.placeholder.pack(anchor="nw", pady=(2, 0))

        ttk.Label(
            main,
            text="URL checks can find warning signs, but cannot prove a link is safe or identify its creator.",
            style="Subtitle.TLabel",
            wraplength=740,
        ).pack(anchor="w", pady=(12, 0))
        root.bind("<Control-l>", self._focus_url)
        root.bind("<Control-Return>", lambda _event: self.check_link())

    def _focus_url(self, _event: tk.Event) -> str:
        self.url_entry.focus_set()
        self.url_entry.selection_range(0, tk.END)
        return "break"

    def check_link(self) -> None:
        try:
            result = analyze_url(self.url_entry.get())
        except ValueError as error:
            self.error_label.configure(text=str(error))
            self.url_entry.focus_set()
            return
        self.error_label.configure(text="")
        self._show_result(result)

    def paste_link(self) -> None:
        try:
            value = self.root.clipboard_get()
        except tk.TclError:
            self.error_label.configure(text="The clipboard does not contain readable text.")
            return
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, value.strip())
        self.error_label.configure(text="")
        self.url_entry.focus_set()

    def clear_input(self) -> None:
        self.url_entry.delete(0, tk.END)
        self.error_label.configure(text="")
        self.current_result = None
        self.result_version += 1
        self.details_canvas = None
        self.copy_status = None
        self.ai_status = None
        self.ai_button = None
        for child in self.results.winfo_children():
            child.destroy()
        ttk.Label(
            self.results,
            text="Your results will appear here.\n\nPaste a link above and select Check link to begin.",
            style="Body.TLabel",
            justify="left",
        ).pack(anchor="nw", pady=(2, 0))
        self.url_entry.focus_set()

    def show_safe_self_test(self) -> None:
        results = run_safe_self_test()
        passed_count = sum(result.passed for result in results)

        window = tk.Toplevel(self.root)
        window.title("LinkShield | Safe self-test")
        window.geometry("900x500")
        window.minsize(720, 380)
        window.transient(self.root)

        content = ttk.Frame(window, padding=22)
        content.pack(fill="both", expand=True)
        ttk.Label(
            content,
            text="Safe analyzer self-test",
            style="Title.TLabel",
        ).pack(anchor="w")
        summary_color = "#157347" if passed_count == len(results) else "#b42318"
        ttk.Label(
            content,
            text=f"{passed_count} of {len(results)} checks passed",
            foreground=summary_color,
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(4, 6))
        ttk.Label(
            content,
            text=(
                "These are simulated examples using reserved .example domains and a "
                "documentation-only IP. They are analyzed locally: no link is opened "
                "and no reputation service is contacted. This verifies app behavior, "
                "not real-world detection accuracy."
            ),
            style="Subtitle.TLabel",
            wraplength=840,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))

        table_frame = ttk.Frame(content)
        table_frame.pack(fill="both", expand=True)
        columns = ("case", "example", "expected", "actual", "status")
        table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        table.heading("case", text="Test")
        table.heading("example", text="Safe example URL")
        table.heading("expected", text="Expected")
        table.heading("actual", text="Detected")
        table.heading("status", text="Result")
        table.column("case", width=150, stretch=True)
        table.column("example", width=235, stretch=True)
        table.column("expected", width=155, stretch=True)
        table.column("actual", width=155, stretch=True)
        table.column("status", width=75, stretch=False, anchor="center")
        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=table.yview,
        )
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        table.tag_configure("pass", foreground="#157347")
        table.tag_configure("fail", foreground="#b42318")

        for result in results:
            expected = result.case.expected_risk or "Invalid URL"
            table.insert(
                "",
                "end",
                values=(
                    result.case.name,
                    result.case.url,
                    expected,
                    result.actual,
                    "PASS" if result.passed else "FAIL",
                ),
                tags=("pass" if result.passed else "fail",),
            )

        details = tk.StringVar(value="Select a row to read what it checks.")
        ttk.Label(
            content,
            textvariable=details,
            style="Body.TLabel",
            wraplength=840,
        ).pack(anchor="w", pady=(12, 0))

        def show_case_detail(_event: tk.Event) -> None:
            selected = table.selection()
            if not selected:
                return
            index = table.index(selected[0])
            details.set(results[index].case.description)

        table.bind("<<TreeviewSelect>>", show_case_detail)

    def _on_mousewheel(self, event: tk.Event) -> str | None:
        canvas = self.details_canvas
        if canvas is None or not canvas.winfo_exists() or not canvas.winfo_ismapped():
            return None

        hovered_widget = getattr(event, "widget", None)
        while hovered_widget is not None and hovered_widget is not canvas:
            hovered_widget = getattr(hovered_widget, "master", None)
        if hovered_widget is None:
            return None

        if getattr(event, "num", None) == 4:
            units = -1
        elif getattr(event, "num", None) == 5:
            units = 1
        else:
            delta = getattr(event, "delta", 0)
            if not delta:
                return None
            units = -int(delta / 120)
            if units == 0:
                units = -1 if delta > 0 else 1
        canvas.yview_scroll(units, "units")
        return "break"

    def _show_result(self, result: AnalysisResult) -> None:
        self.result_version += 1
        self.details_canvas = None
        for child in self.results.winfo_children():
            child.destroy()

        palette = {
            "High risk indicators": ("#b42318", "#fff1f0"),
            "Some warning signs": ("#a15c00", "#fff7e6"),
            "No obvious warning signs": ("#157347", "#eaf7ef"),
        }[result.risk]
        risk_color, risk_background = palette
        risk_card = tk.Frame(
            self.results,
            bg=risk_background,
            highlightthickness=0,
            padx=14,
            pady=11,
        )
        risk_card.pack(fill="x", pady=(0, 12))
        tk.Frame(risk_card, width=4, bg=risk_color).pack(
            side="left",
            fill="y",
            padx=(0, 12),
        )
        risk_text = tk.Frame(risk_card, bg=risk_background)
        risk_text.pack(side="left", fill="x", expand=True)
        tk.Label(
            risk_text,
            text=result.risk.upper(),
            bg=risk_background,
            fg=risk_color,
            font=("Segoe UI", 15, "bold"),
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            risk_text,
            text=self._risk_summary(result),
            bg=risk_background,
            fg="#43516a",
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=590,
        ).pack(anchor="w", pady=(2, 0))

        result_actions = ttk.Frame(self.results, style="Card.TFrame")
        result_actions.pack(fill="x", pady=(0, 4))
        ttk.Label(
            result_actions,
            text=f"URL indicator score  {result.score}/100  ·  not a probability",
            style="Body.TLabel",
        ).pack(side="left", anchor="w")
        self.copy_button = ttk.Button(
            result_actions,
            text="Copy result",
            style="Secondary.TButton",
            command=self.copy_result,
        )
        self.copy_button.pack(side="right")
        self.copy_status = ttk.Label(
            self.results,
            text="",
            style="Subtitle.TLabel",
        )
        self.copy_status.pack(anchor="e", pady=(0, 6))

        self.feed_button = ttk.Button(
            self.results,
            text="Check OpenPhish feed",
            command=self.check_public_feed,
        )
        self.feed_button.pack(anchor="w")
        ttk.Label(
            self.results,
            text="Optional: download a public phishing list and compare the URL locally.",
            style="Body.TLabel",
            wraplength=640,
        ).pack(anchor="w", pady=(4, 3))
        self.feed_status = ttk.Label(
            self.results,
            text="Optional online check. No feed is downloaded unless you choose this.",
            style="Subtitle.TLabel",
            wraplength=640,
        )
        self.feed_status.pack(anchor="w", pady=(0, 12))

        self.ai_button = ttk.Button(
            self.results,
            text=(
                "Explain with Gemini"
                if self.gemini.is_configured
                else "Set up Gemini explanation"
            ),
            command=self.request_gemini_explanation,
        )
        self.ai_button.pack(anchor="w")
        ttk.Label(
            self.results,
            text=(
                "Optional AI explanation. It does not determine the risk verdict."
            ),
            style="Body.TLabel",
            wraplength=640,
        ).pack(anchor="w", pady=(4, 3))
        self.ai_status = ttk.Label(
            self.results,
            text=(
                "No data is sent until you review and confirm an explanation request."
            ),
            style="Subtitle.TLabel",
            wraplength=640,
        )
        self.ai_status.pack(anchor="w", pady=(0, 12))
        self.current_result = result

        details_button = ttk.Button(self.results, text="Show details  +")
        details_button.pack(anchor="w")

        details_area = ttk.Frame(self.results, style="Card.TFrame")
        details_canvas = tk.Canvas(
            details_area,
            background="#ffffff",
            highlightthickness=0,
            height=280,
        )
        details_scrollbar = ttk.Scrollbar(
            details_area,
            orient="vertical",
            command=details_canvas.yview,
        )
        details_canvas.configure(yscrollcommand=details_scrollbar.set)
        self.details_canvas = details_canvas
        details_canvas.pack(side="left", fill="both", expand=True, pady=(10, 0))
        details_scrollbar.pack(side="right", fill="y", pady=(10, 0))

        details_content = ttk.Frame(details_canvas, style="Card.TFrame")
        content_window = details_canvas.create_window(
            (0, 0),
            window=details_content,
            anchor="nw",
        )
        details_content.bind(
            "<Configure>",
            lambda _event: details_canvas.configure(
                scrollregion=details_canvas.bbox("all")
            ),
        )
        details_canvas.bind(
            "<Configure>",
            lambda event: details_canvas.itemconfigure(
                content_window,
                width=event.width,
            ),
        )

        def toggle_details() -> None:
            if details_area.winfo_manager():
                details_area.pack_forget()
                details_button.configure(text="Show details  +")
            else:
                details_area.pack(fill="both", expand=True)
                details_button.configure(text="Hide details  −")
                details_canvas.update_idletasks()
                details_canvas.configure(scrollregion=details_canvas.bbox("all"))

        details_button.configure(command=toggle_details)
        self._section(details_content, "Link checked", result.url)
        self._section(details_content, "Destination domain", result.domain)
        self._section(
            details_content,
            "Site owner",
            "Not determined. This version does not look up domain-registration records.",
        )
        if result.possible_impersonation:
            self._section(
                details_content,
                "Possible disguise",
                f"May be imitating {result.possible_impersonation}. This is a URL clue, not confirmation.",
            )
        else:
            self._section(
                details_content,
                "Possible disguise",
                "No known brand match found in this basic check.",
            )
        self._section(details_content, "What the link may be about", result.page_hint)

        ttk.Label(
            details_content,
            text="What we noticed",
            style="CardTitle.TLabel",
        ).pack(anchor="w", pady=(4, 5))
        for finding in result.findings:
            item = ttk.Frame(details_content, style="Card.TFrame")
            item.pack(fill="x", pady=4)
            ttk.Label(item, text=f"•  {finding.title}", style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(
                item,
                text=finding.detail,
                style="Body.TLabel",
                wraplength=640,
            ).pack(anchor="w", padx=(19, 0), pady=(2, 0))

    def configure_gemini_key(self) -> None:
        key = simpledialog.askstring(
            "Gemini API key",
            (
                "Paste your Google Gemini API key. It is kept in memory only "
                "and is not saved to disk. Leave the field blank to remove the "
                "current key."
            ),
            parent=self.root,
            show="*",
        )
        if key is None:
            return
        try:
            self.gemini.set_api_key(key)
        except ValueError as error:
            messagebox.showerror("Invalid API key", str(error), parent=self.root)
            return

        if self.ai_button is not None and self.ai_button.winfo_exists():
            self.ai_button.configure(
                text=(
                    "Explain with Gemini"
                    if self.gemini.is_configured
                    else "Set up Gemini explanation"
                ),
                state="normal",
            )
        if self.ai_status is not None and self.ai_status.winfo_exists():
            self.ai_status.configure(
                text=(
                    "Gemini key is ready for this session. Nothing is sent "
                    "until you request and confirm an explanation."
                    if self.gemini.is_configured
                    else "Gemini key removed from this session."
                )
            )

    def request_gemini_explanation(self) -> None:
        if self.current_result is None:
            return
        if not self.gemini.is_configured:
            self.configure_gemini_key()
            return

        confirmed = messagebox.askyesno(
            "Send limited details to Gemini?",
            (
                "If you continue, Google Gemini receives the destination domain, "
                "HTTP/HTTPS scheme, LinkShield risk rating, and URL-pattern findings "
                "to explain them.\n\n"
                "The full URL, path, query parameters, fragment, and embedded "
                "credentials are not sent. LinkShield does not open the site. "
                "Google's service processes the submitted evidence under its terms "
                "and privacy policy. Continue?"
            ),
            parent=self.root,
            icon="warning",
        )
        if not confirmed:
            return

        result = self.current_result
        version = self.result_version
        self.ai_button.configure(state="disabled", text="Asking Gemini...")
        self.ai_status.configure(text="Sending the limited evidence after your confirmation...")
        Thread(
            target=self._gemini_explanation_worker,
            args=(result, version),
            daemon=True,
        ).start()

    def _gemini_explanation_worker(
        self,
        result: AnalysisResult,
        version: int,
    ) -> None:
        try:
            explanation = self.gemini.explain(result)
        except GeminiApiError as error:
            self.root.after(0, self._show_gemini_error, version, str(error))
            return
        self.root.after(
            0,
            self._show_gemini_explanation,
            version,
            explanation.text,
        )

    def _show_gemini_error(self, version: int, message: str) -> None:
        if version != self.result_version:
            return
        self.ai_button.configure(
            state="normal",
            text="Try Gemini explanation again",
        )
        self.ai_status.configure(text=f"Gemini explanation unavailable: {message}")

    def _show_gemini_explanation(self, version: int, text: str) -> None:
        if version != self.result_version:
            return
        self.ai_button.configure(
            state="normal",
            text="Explain with Gemini again",
        )
        self.ai_status.configure(text="Explanation generated. It is not a safety verdict.")

        window = tk.Toplevel(self.root)
        window.title("LinkShield | AI explanation")
        window.geometry("640x460")
        window.minsize(480, 340)
        window.transient(self.root)

        content = ttk.Frame(window, padding=22)
        content.pack(fill="both", expand=True)
        ttk.Label(
            content,
            text="Gemini explanation",
            style="Title.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            content,
            text=(
                "AI-generated explanation of URL-pattern evidence only. "
                "It may be inaccurate and does not change LinkShield's result."
            ),
            style="Subtitle.TLabel",
            wraplength=590,
        ).pack(anchor="w", pady=(4, 14))
        answer = tk.Text(
            content,
            wrap="word",
            height=12,
            font=("Segoe UI", 11),
            relief="flat",
            padx=12,
            pady=12,
            background="#ffffff",
            foreground="#263651",
        )
        scrollbar = ttk.Scrollbar(content, orient="vertical", command=answer.yview)
        answer.configure(yscrollcommand=scrollbar.set)
        answer.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        answer.insert("1.0", text)
        answer.configure(state="disabled")

    @staticmethod
    def _risk_summary(result: AnalysisResult) -> str:
        if result.risk == "High risk indicators":
            return "Several URL patterns deserve caution. Avoid opening this link unless independently verified."
        if result.risk == "Some warning signs":
            return "The URL has one or more warning signs. Check the destination carefully before proceeding."
        return "No common warning signs were detected. This does not confirm the site is safe."

    def copy_result(self) -> None:
        result = self.current_result
        if result is None:
            return
        summary = [
            f"LinkShield result: {result.risk}",
            f"URL indicator score: {result.score}/100 (not a probability)",
            f"Destination: {result.domain}",
            f"Link: {result.url}",
            "",
            "Findings:",
            *(f"- {finding.title}: {finding.detail}" for finding in result.findings),
            "",
            "URL checks are indicators, not proof that a website is safe or malicious.",
        ]
        if self.copy_status is not None:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(summary))
                self.root.update_idletasks()
            except tk.TclError:
                self.copy_status.configure(
                    text="Could not access the clipboard. Try again."
                )
                return
            self.copy_status.configure(text="Result copied to clipboard.")

    def _section(self, parent: ttk.Frame, title: str, value: str) -> None:
        ttk.Label(parent, text=title, style="CardTitle.TLabel").pack(anchor="w", pady=(0, 3))
        ttk.Label(parent, text=value, style="Body.TLabel", wraplength=640).pack(anchor="w", pady=(0, 10))

    def check_public_feed(self) -> None:
        if self.current_result is None:
            return
        url = self.current_result.url
        version = self.result_version
        self.feed_button.configure(state="disabled", text="Checking public feed...")
        self.feed_status.configure(text="Downloading the public list and comparing locally...")
        Thread(
            target=self._check_public_feed_worker,
            args=(url, version),
            daemon=True,
        ).start()

    def _check_public_feed_worker(self, url: str, version: int) -> None:
        try:
            result = self.feed_checker.check(url)
        except (ReputationFeedError, ValueError) as error:
            self.root.after(0, self._show_feed_error, version, str(error))
            return
        self.root.after(
            0,
            self._show_feed_result,
            version,
            result.listed,
            result.entries_checked,
        )

    def _show_feed_error(self, version: int, message: str) -> None:
        if version != self.result_version:
            return
        self.feed_button.configure(state="normal", text="Retry OpenPhish check")
        self.feed_status.configure(text=f"Feed check unavailable: {message}")

    def _show_feed_result(
        self,
        version: int,
        listed: bool,
        entries_checked: int,
    ) -> None:
        if version != self.result_version:
            return
        self.feed_button.configure(state="normal", text="Check OpenPhish feed again")
        if listed:
            message = (
                f"Exact URL match found in the OpenPhish feed "
                f"({entries_checked:,} entries). Treat this as a strong warning."
            )
            color = "#b42318"
        else:
            message = (
                f"No exact URL match found in the OpenPhish feed "
                f"({entries_checked:,} entries). This does not mean the link is safe."
            )
            color = "#43516a"
        self.feed_status.configure(text=message, foreground=color)


def run() -> None:
    root = tk.Tk()
    DetectorWindow(root)
    root.mainloop()
