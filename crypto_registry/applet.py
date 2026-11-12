#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-crypto-registry"
APPLET_NAME = "Crypto Registry"
APPLET_VERSION = "0.0.8"
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"
APPLET_PUBLISHER = "brunonlinespace"
APPLET_ORGANIZATION_ID = "linspectacles"
APPLET_ORGANIZATION_URL = "https://github.com/linspectacles/"
APPLET_REPOSITORY = "https://github.com/linspectacles/crypto-registry"

from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ._support import BaseInspectorTab, export_records_dialog, metadata_font_qss


PROC_CRYPTO = Path("/proc/crypto")


def _parse_priority(value):
    try:
        return int(str(value).strip(), 10)
    except (TypeError, ValueError):
        return None


def _parse_crypto_registry(text):
    """Parse /proc/crypto into complete, ordered registry records."""
    records = []
    current = []

    def finish_record():
        nonlocal current
        if not current:
            return

        grouped = {}
        for key, value in current:
            grouped.setdefault(key.lower(), []).append(value)

        def first(key, default=""):
            values = grouped.get(key.lower(), [])
            return values[0] if values else default

        record = {
            "name": first("name"),
            "type": first("type") or "Not reported",
            "driver": first("driver"),
            "module": first("module"),
            "priority": _parse_priority(first("priority")),
            "_reported_fields": list(current),
        }
        records.append(record)
        current = []

    for raw_line in str(text or "").splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip():
            finish_record()
            continue
        if ":" not in line:
            # Preserve unusual/unstructured lines rather than silently dropping them.
            current.append(("reported", line.strip()))
            continue
        key, value = line.split(":", 1)
        current.append((key.strip(), value.strip()))

    finish_record()
    return records


def _populate_sources(widget, source_text):
    """Present the existing Sources copy with Journal-style section formatting."""
    heading = QTextCharFormat()
    heading.setForeground(QColor("#9cdcfe"))
    heading.setFontWeight(600)
    body = QTextCharFormat()
    body.setForeground(QColor("#dcdcdc"))

    widget.clear()
    cursor = widget.textCursor()
    for index, line in enumerate(str(source_text).splitlines(keepends=True)):
        # The opening sentence is introductory text; subsequent unindented
        # lines are section headings. Indented source/notes remain body text.
        is_heading = index > 0 and bool(line.strip()) and not line[0].isspace()
        cursor.insertText(line, heading if is_heading else body)
    widget.setTextCursor(cursor)
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    widget.setTextCursor(cursor)
    widget.verticalScrollBar().setValue(0)


class CryptoRegistryOptionsDialog(QDialog):
    """Established LinSpectacles Options treatment, adapted from Kernel Modules."""

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — Crypto Registry")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # Appearance
        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)

        appearance_heading = QLabel("Metadata display")
        heading_font = appearance_heading.font()
        heading_font.setBold(True)
        appearance_heading.setFont(heading_font)
        appearance_layout.addWidget(appearance_heading)

        appearance_note = QLabel(
            "Choose how the inventory and Metadata Details panes are arranged. "
            "This Crypto Registry setting is remembered."
        )
        appearance_note.setWordWrap(True)
        appearance_layout.addWidget(appearance_note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentText(
            "Vertical" if owner.details_orientation == "vertical" else "Horizontal"
        )
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        shortcut_note = QLabel(
            "Shortcuts: F3 shows/hides Metadata Details; Ctrl+L toggles "
            "Horizontal/Vertical; Shift+F5 refreshes the registry; Ctrl+/ opens Options."
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)
        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, "Appearance")

        # Sources
        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)

        sources_heading = QLabel("Data Sources")
        sources_heading_font = sources_heading.font()
        sources_heading_font.setBold(True)
        sources_heading_font.setPointSize(max(sources_heading_font.pointSize(), 11))
        sources_heading.setFont(sources_heading_font)
        sources_layout.addWidget(sources_heading)

        sources_note = QLabel(
            "Linux interface used by this read-only Kernel Crypto API registry inspector."
        )
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        sources_text = QTextEdit()
        sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = getattr(owner, "_metadata_font", None)
        if chosen_font is not None:
            sources_text.setFont(chosen_font)
            sources_text.document().setDefaultFont(chosen_font)
            sources_text.setCurrentFont(chosen_font)
            font_rule = metadata_font_qss(chosen_font)
        else:
            font_rule = ""
        sources_text.setStyleSheet(
            "QTextEdit { "
            f"{font_rule} "
            "background-color: #151719; color: #dcdcdc; border: 1px solid #333333; "
            "}"
        )
        _populate_sources(sources_text, owner.sources_text())
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        # Export
        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)

        export_heading = QLabel("Export details")
        export_heading_font = export_heading.font()
        export_heading_font.setBold(True)
        export_heading.setFont(export_heading_font)
        export_layout.addWidget(export_heading)

        export_note = QLabel(
            "Select the Crypto Registry details to include in the export."
        )
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)

        self.export_name = QCheckBox("Name")
        self.export_type = QCheckBox("Type")
        self.export_driver = QCheckBox("Driver")
        self.export_module = QCheckBox("Module")
        self.export_priority = QCheckBox("Priority")
        self.export_metadata = QCheckBox("Metadata Details")

        for checkbox in (
            self.export_name,
            self.export_type,
            self.export_driver,
            self.export_module,
            self.export_priority,
        ):
            checkbox.setChecked(True)
        self.export_metadata.setChecked(False)

        for checkbox in (
            self.export_name,
            self.export_type,
            self.export_driver,
            self.export_module,
            self.export_priority,
            self.export_metadata,
        ):
            export_layout.addWidget(checkbox)

        export_layout.addStretch(1)
        export_row = QHBoxLayout()
        export_row.addStretch(1)
        export_button = QPushButton("Export...")
        export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button)
        export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        # About
        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(
                    pixmap.scaled(
                        112,
                        112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>Crypto Registry</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        description = QLabel(
            "A read-only LinSpectacles applet for inspecting implementations currently "
            "registered with the Linux Kernel Crypto API."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(description)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            f"<a href='{APPLET_ORGANIZATION_URL}'>{APPLET_ORGANIZATION_ID}</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        applet_root = Path(__file__).resolve().parent.parent
        readme_url = QUrl.fromLocalFile(str(applet_root / "README.md")).toString()
        license_url = QUrl.fromLocalFile(str(applet_root / "LICENSE")).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{APPLET_REPOSITORY}'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _export_selected(self):
        selected = []
        if self.export_name.isChecked():
            selected.append(("name", "Name", 180, "left"))
        if self.export_type.isChecked():
            selected.append(("type", "Type", 120, "left"))
        if self.export_driver.isChecked():
            selected.append(("driver", "Driver", 220, "left"))
        if self.export_module.isChecked():
            selected.append(("module", "Module", 150, "left"))
        if self.export_priority.isChecked():
            selected.append(("priority", "Priority", 85, "right"))
        if self.export_metadata.isChecked():
            selected.append(("metadata_details", "Metadata Details", 520, "left"))

        if not selected:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return

        records = []
        include_metadata = self.export_metadata.isChecked()
        for record in self.owner.get_export_records():
            exported = dict(record)
            if exported.get("priority") is None:
                exported["priority"] = ""
            if include_metadata:
                exported["metadata_details"] = self.owner.metadata_details_for_export(record)
            records.append(exported)

        if not records:
            QMessageBox.information(self, "Export", "There is no collected data to export yet.")
            return

        path = export_records_dialog(
            self,
            APPLET_NAME,
            records,
            columns=selected,
        )
        if path is not None:
            self.owner.set_status(f"Exported data to {path}")


class CryptoRegistryTab(BaseInspectorTab):
    NUMERIC_COLUMNS = {"priority"}

    def __init__(self, parent=None):
        columns = [
            ("name", "Name", 180, "left"),
            ("type", "Type", 120, "left"),
            ("module", "Module", 150, "left"),
            ("priority", "Priority", 85, "right"),
            ("driver", "Driver", 220, "left"),
        ]
        super().__init__("Total Crypto Registry Entries", columns, ["All Types"], parent)
        self.export_title = APPLET_NAME

        self.category_label.setText("Type:")
        self.search_entry.setPlaceholderText("Search crypto registry...")

        self.details_orientation = "horizontal"
        self._load_details_orientation()
        self._load_metadata_visibility()

        self.export_btn.setText("Options...")
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self._install_shortcuts()
        self.load_modules()

    def _install_shortcuts(self):
        self._metadata_shortcut = QShortcut(QKeySequence("F3"), self)
        self._metadata_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._metadata_shortcut.activated.connect(self.toggle_metadata_panel)

        self._layout_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self._layout_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._layout_shortcut.activated.connect(self.toggle_details_orientation)

        self._refresh_shortcut = QShortcut(QKeySequence("Shift+F5"), self)
        self._refresh_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._refresh_shortcut.activated.connect(self.load_modules)

        self._options_shortcut = QShortcut(QKeySequence("Ctrl+/"), self)
        self._options_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._options_shortcut.activated.connect(self.show_options)

    def _load_metadata_visibility(self):
        settings = QSettings("brunonlinespace", "Crypto Registry")
        visible = settings.value("metadata_panel_visible", True)
        if isinstance(visible, str):
            visible = visible.strip().lower() not in {"0", "false", "no", "off"}
        self.set_metadata_panel_visible(bool(visible), persist=False)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        panel = self.splitter.widget(1)
        if panel is not None:
            panel.setVisible(self.metadata_panel_visible)
        if persist:
            settings = QSettings("brunonlinespace", "Crypto Registry")
            settings.setValue("metadata_panel_visible", self.metadata_panel_visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible)

    def toggle_details_orientation(self):
        self.set_details_orientation(
            "vertical" if self.details_orientation == "horizontal" else "horizontal"
        )

    def _rebuild_type_filter(self):
        previous = self.category_dropdown.currentText() or "All Types"
        types = sorted(
            {str(record.get("type") or "Not reported") for record in self.modules_data},
            key=str.lower,
        )
        choices = ["All Types"] + types
        self.category_dropdown.blockSignals(True)
        try:
            self.category_dropdown.clear()
            self.category_dropdown.addItems(choices)
            self.category_dropdown.setCurrentText(previous if previous in choices else "All Types")
        finally:
            self.category_dropdown.blockSignals(False)

    def load_modules(self):
        self.modules_data.clear()
        try:
            text = PROC_CRYPTO.read_text(encoding="utf-8", errors="replace")
            self.modules_data.extend(_parse_crypto_registry(text))
            self._rebuild_type_filter()
            self.stats_label.setText(f"{self.total_label_text}: {len(self.modules_data)}")
            self.filter_modules()
            self.set_status("Successfully refreshed the kernel crypto registry.")
        except FileNotFoundError:
            self._rebuild_type_filter()
            self.stats_label.setText(f"{self.total_label_text}: 0")
            self.filter_modules()
            self.set_status("Warning: /proc/crypto was not found on this system.")
        except PermissionError:
            self._rebuild_type_filter()
            self.stats_label.setText(f"{self.total_label_text}: 0")
            self.filter_modules()
            self.set_status("Access to /proc/crypto is restricted.")
        except OSError as exc:
            self._rebuild_type_filter()
            self.stats_label.setText(f"{self.total_label_text}: 0")
            self.filter_modules()
            self.set_status(f"Error reading /proc/crypto: {exc}")

    def filter_modules(self, *_):
        query = self.search_entry.text().strip().lower()
        selected_type = self.category_dropdown.currentText() or "All Types"

        matches = []
        for record in self.modules_data:
            match_type = selected_type == "All Types" or record.get("type") == selected_type
            match_query = not query or any(
                query in str(value).lower() for value in record.values()
            )
            if match_type and match_query:
                matches.append(record)

        blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setCurrentCell(-1, -1)
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))

            for row, record in enumerate(matches):
                for column_index, (column_id, _label, _width, alignment) in enumerate(self.columns):
                    value = record.get(column_id, "")
                    if column_id == "priority" and value is None:
                        display = ""
                    elif column_id in self.NUMERIC_COLUMNS and isinstance(value, int):
                        display = f"{value:,}"
                    else:
                        display = str(value)

                    item = QTableWidgetItem(display)
                    if column_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    if alignment == "right":
                        item.setTextAlignment(
                            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                        )
                    else:
                        item.setTextAlignment(
                            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                        )
                    self.style_table_item(item, column_id, record)
                    self.table.setItem(row, column_index, item)

            if matches:
                self.table.setCurrentCell(0, 0)
                self.table.selectRow(0)
        finally:
            self.table.blockSignals(blocked)

        if matches:
            self.on_module_select()
        else:
            self.clear_info()

        self.export_btn.setEnabled(bool(self.modules_data))
        if query or selected_type != "All Types":
            self.filter_status_lbl.setText(
                f"(Showing {len(matches)} of {len(self.modules_data)} items)"
            )
        else:
            self.filter_status_lbl.clear()

    def sort_by(self, column_id):
        if column_id != "priority":
            return super().sort_by(column_id)

        reverse = self._sort_reverse.get(column_id, False)
        self.modules_data.sort(
            key=lambda item: item.get("priority") if isinstance(item.get("priority"), int) else -1,
            reverse=reverse,
        )
        self._sort_reverse[column_id] = not reverse
        self.filter_modules()

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return
        self._render_record_details(record)
        identity = record.get("driver") or record.get("name") or "selected entry"
        self.set_status(f"Inspecting reported crypto registration metadata for [{identity}].")

    def _render_record_details(self, record):
        self.clear_info()
        self.append_info("--- Reported Crypto Registration ---\n")

        reported_fields = list(record.get("_reported_fields") or [])
        if reported_fields:
            for key, value in reported_fields:
                self.append_key_value(key, value)
        else:
            self.append_info("No reported fields were available for this registry entry.\n")

        self.append_info("\n--- Interpretation ---\n")
        self.append_key_value(
            "Registry Meaning",
            "Implementation currently registered with the Linux Kernel Crypto API",
        )
        self.append_key_value(
            "Active Use",
            "Not determined by this registry record",
        )
        self.append_key_value(
            "Entry Handling",
            "Each /proc/crypto record is preserved separately; matching algorithm names are not deduplicated",
        )

        self.info_text.moveCursor(QTextCursor.MoveOperation.Start)
        self.info_text.verticalScrollBar().setValue(0)

    @staticmethod
    def sources_text():
        return (
            "Crypto Registry is read-only. Its displayed facts come from this Linux kernel interface.\n\n"
            "Registered Kernel Crypto API implementations and their reported properties\n"
            "  /proc/crypto\n\n"
            "Important distinctions\n"
            "  Each blank-line-delimited /proc/crypto record is treated as one registry entry.\n"
            "  Multiple entries may report the same algorithm name with different drivers or implementation properties; Crypto Registry does not deduplicate them.\n"
            "  The fields exposed by /proc/crypto vary by implementation type and kernel. Crypto Registry preserves every reported key/value field in Metadata Details.\n"
            "  Registration means that an implementation is available to the Kernel Crypto API. This applet does not infer that a specific implementation is currently being used by a workload.\n"
            "  Crypto Registry never writes to /proc/crypto or changes kernel cryptographic configuration."
        )

    def show_options(self):
        dialog = CryptoRegistryOptionsDialog(self)
        dialog.exec()

    def _load_details_orientation(self):
        settings = QSettings("brunonlinespace", "Crypto Registry")
        orientation = str(
            settings.value("details_orientation", "horizontal") or "horizontal"
        ).lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation

        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])

        if persist:
            settings = QSettings("brunonlinespace", "Crypto Registry")
            settings.setValue("details_orientation", orientation)
            settings.sync()

    def metadata_details_for_export(self, record):
        """Render the same metadata text for one record without changing the visible pane."""
        original_info = self.info_text
        temp = QTextEdit()
        self.info_text = temp
        try:
            self._render_record_details(record)
            return temp.toPlainText()
        finally:
            self.info_text = original_info


def create_applet(parent=None):
    return CryptoRegistryTab(parent=parent)


def run_standalone():
    import sys

    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow

    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1200, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()
