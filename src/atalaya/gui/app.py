"""Main window for the atalaya desktop console."""

from __future__ import annotations

from importlib import resources

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QClipboard, QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from atalaya.core import entropy, hibp, passphrase
from atalaya.core.generator import PASSWORD_LENGTH, GeneratorOptions, generate_password
from atalaya.core.vault import Vault, VaultNotInitialized, WrongMasterPassword
from atalaya.gui.widgets import EntropyMeter, ToggleSwitch

_MAX_MEANINGFUL_BITS = 130.0


def _load_fonts() -> None:
    for name in ("JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf"):
        path = resources.files("atalaya.gui.assets").joinpath(name)
        with resources.as_file(path) as font_path:
            QFontDatabase.addApplicationFont(str(font_path))


class HibpWorker(QThread):
    finished_with_result = Signal(object)

    def __init__(self, password: str, parent=None):
        super().__init__(parent)
        self._password = password

    def run(self):
        result = hibp.check_password(self._password)
        self.finished_with_result.emit(result)


class SectionLabel(QLabel):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setObjectName("SectionLabel")


class HistoryDialog(QDialog):
    """Browses saved entries and reveals a password only after the vault's
    master password checks out — site/username are visible without it."""

    def __init__(self, vault: Vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self._entries: list = []

        self.setWindowTitle("HISTORIAL DE CONTRASENAS")
        self.setMinimumSize(680, 420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["FECHA", "SITIO", "USUARIO", "ENTROPIA", "MODO"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

        button_row = QHBoxLayout()
        self.reveal_button = QPushButton("VER / COPIAR")
        self.delete_button = QPushButton("ELIMINAR")
        self.refresh_button = QPushButton("REFRESCAR")
        button_row.addWidget(self.reveal_button)
        button_row.addWidget(self.delete_button)
        button_row.addStretch(1)
        button_row.addWidget(self.refresh_button)
        layout.addLayout(button_row)

        self.reveal_button.clicked.connect(self._reveal_selected)
        self.delete_button.clicked.connect(self._delete_selected)
        self.refresh_button.clicked.connect(self._reload)

        self._reload()

    def _reload(self) -> None:
        self._entries = self.vault.list_entries()
        self.table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            date = entry.created_at.split("T")[0]
            self.table.setItem(row, 0, QTableWidgetItem(date))
            self.table.setItem(row, 1, QTableWidgetItem(entry.site))
            self.table.setItem(row, 2, QTableWidgetItem(entry.username or "-"))
            self.table.setItem(row, 3, QTableWidgetItem(f"{entry.bits:.1f} bits ({entry.label})"))
            self.table.setItem(row, 4, QTableWidgetItem(entry.mode))

    def _selected_entry(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self._entries):
            return None
        return self._entries[row]

    def _reveal_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return

        master, ok = QInputDialog.getText(
            self, "Contrasena maestra", "Contrasena maestra del historial:", QLineEdit.Password
        )
        if not ok or not master:
            return

        try:
            password = self.vault.reveal(entry.id, master)
        except WrongMasterPassword:
            QMessageBox.warning(self, "Error", "Contrasena maestra incorrecta.")
            return
        except VaultNotInitialized:
            QMessageBox.warning(self, "Error", "No hay historial guardado todavia.")
            return

        QApplication.clipboard().setText(password)
        QMessageBox.information(
            self, "Copiado", f"Contrasena de '{entry.site}' copiada al portapapeles."
        )

    def _delete_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return

        confirm = QMessageBox.question(
            self, "Eliminar entrada", f"Eliminar la entrada de '{entry.site}'?"
        )
        if confirm != QMessageBox.Yes:
            return

        self.vault.delete(entry.id)
        self._reload()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ATALAYA // consola de contrasenas")
        self.setMinimumSize(760, 560)

        self._current_password = ""
        self._pool_size = 0
        self._hibp_worker: HibpWorker | None = None

        self._build_ui()
        self._wire_signals()
        self._regenerate()

    # -- layout -----------------------------------------------------------

    def _build_ui(self) -> None:
        chassis = QWidget()
        chassis.setObjectName("Chassis")
        self.setCentralWidget(chassis)

        root = QVBoxLayout(chassis)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        root.addLayout(self._build_header())
        root.addWidget(self._build_readout_panel())

        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self._build_mode_panel(), 1)
        body.addWidget(self._build_options_panel(), 1)
        root.addLayout(body)

        root.addWidget(self._build_security_panel())
        root.addWidget(self._build_history_save_panel())
        root.addStretch(1)
        root.addWidget(self._build_status_strip())

    def _build_header(self) -> QHBoxLayout:
        layout = QHBoxLayout()

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        title = QLabel("ATALAYA")
        title.setObjectName("BrandTitle")
        subtitle = QLabel("CONSOLA DE CONTRASENAS CRIPTOGRAFICAS - RNG SOLO CON SECRETS")
        subtitle.setObjectName("BrandSubtitle")
        text_col.addWidget(title)
        text_col.addWidget(subtitle)

        self.history_button = QPushButton("HISTORIAL")
        self.history_button.setObjectName("CopyButton")

        layout.addLayout(text_col)
        layout.addStretch(1)
        layout.addWidget(self.history_button, 0, Qt.AlignTop)
        return layout

    def _build_readout_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("ReadoutPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(4, 4, 4, 12)
        layout.setSpacing(8)

        self.readout = QLabel("")
        self.readout.setObjectName("PasswordReadout")
        self.readout.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.readout.setWordWrap(True)
        layout.addWidget(self.readout)

        meter_row = QHBoxLayout()
        meter_row.setContentsMargins(16, 0, 16, 0)
        meter_row.setSpacing(12)

        self.meter = EntropyMeter()
        self.entropy_value = QLabel("0.0 bits")
        self.entropy_value.setObjectName("EntropyValue")
        self.entropy_rating = QLabel("-")
        self.entropy_rating.setObjectName("EntropyRatingLabel")

        meter_row.addWidget(self.meter, 1)
        meter_row.addWidget(self.entropy_value)
        meter_row.addWidget(self.entropy_rating)
        layout.addLayout(meter_row)

        action_row = QHBoxLayout()
        action_row.setContentsMargins(16, 0, 16, 4)
        action_row.setSpacing(10)

        self.generate_button = QPushButton("GENERAR")
        self.generate_button.setObjectName("GenerateButton")
        self.copy_button = QPushButton("COPIAR")
        self.copy_button.setObjectName("CopyButton")

        action_row.addWidget(self.generate_button)
        action_row.addWidget(self.copy_button)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        return panel

    def _build_mode_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        layout.addWidget(SectionLabel("MODO DE GENERACION"))

        self.mode_characters = QRadioButton("CADENA DE CARACTERES")
        self.mode_passphrase = QRadioButton("PASSPHRASE DICEWARE")
        self.mode_characters.setChecked(True)
        layout.addWidget(self.mode_characters)
        layout.addWidget(self.mode_passphrase)

        length_row = QHBoxLayout()
        length_label = QLabel("LONGITUD")
        length_label.setStyleSheet("font-size: 11px; letter-spacing: 1px; color: #C3C9D0;")
        length_fixed_value = QLabel("16 (4 BLOQUES DE 4, FIJO)")
        length_fixed_value.setObjectName("LengthValue")
        length_row.addWidget(length_label)
        length_row.addStretch(1)
        length_row.addWidget(length_fixed_value)
        layout.addLayout(length_row)

        words_row = QHBoxLayout()
        words_label = QLabel("NUMERO DE PALABRAS")
        words_label.setStyleSheet("font-size: 11px; letter-spacing: 1px; color: #C3C9D0;")
        self.words_spin = QSpinBox()
        self.words_spin.setRange(3, 12)
        self.words_spin.setValue(6)
        words_row.addWidget(words_label)
        words_row.addStretch(1)
        words_row.addWidget(self.words_spin)
        layout.addLayout(words_row)

        layout.addStretch(1)
        return panel

    def _build_options_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        layout.addWidget(SectionLabel("CONJUNTO DE CARACTERES"))

        self.check_uppercase = QCheckBox("MAYUSCULAS  A-Z")
        self.check_lowercase = QCheckBox("MINUSCULAS  a-z")
        self.check_digits = QCheckBox("DIGITOS  0-9")
        self.check_symbols = QCheckBox("SIMBOLOS  !@#$...")
        for box in (
            self.check_uppercase,
            self.check_lowercase,
            self.check_digits,
            self.check_symbols,
        ):
            box.setChecked(True)
            layout.addWidget(box)

        self.check_exclude_ambiguous = QCheckBox("EXCLUIR AMBIGUOS  0/O 1/l/I")
        layout.addWidget(self.check_exclude_ambiguous)

        layout.addStretch(1)
        return panel

    def _build_security_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        label = QLabel("COMPROBAR CONTRA HAVE I BEEN PWNED")
        label.setStyleSheet("font-size: 11px; font-weight: bold; letter-spacing: 1px; color: #FF9E66;")
        detail = QLabel(
            "Opcional. Solo se envian los primeros 5 caracteres hex del hash SHA-1\n"
            "(k-anonimato) - la contrasena en claro nunca sale de esta maquina."
        )
        detail.setStyleSheet("font-size: 10px; color: #5B646D;")
        text_col.addWidget(label)
        text_col.addWidget(detail)

        self.hibp_toggle = ToggleSwitch(accent="#FF7A33")

        layout.addLayout(text_col, 1)
        layout.addWidget(self.hibp_toggle)
        return panel

    def _build_history_save_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Panel")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        label = SectionLabel("GUARDAR EN HISTORIAL")
        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("SITIO / SERVICIO")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("USUARIO (OPCIONAL)")

        self.save_history_button = QPushButton("GUARDAR")
        self.save_history_button.setObjectName("CopyButton")

        layout.addWidget(label)
        layout.addWidget(self.site_input, 1)
        layout.addWidget(self.user_input, 1)
        layout.addWidget(self.save_history_button)
        return panel

    def _build_status_strip(self) -> QLabel:
        self.status_strip = QLabel("LISTO")
        self.status_strip.setObjectName("StatusStrip")
        self.status_strip.setProperty("state", "")
        return self.status_strip

    # -- wiring -------------------------------------------------------------

    def _wire_signals(self) -> None:
        self.generate_button.clicked.connect(self._regenerate)
        self.copy_button.clicked.connect(self._copy_current)
        self.mode_characters.toggled.connect(self._on_mode_changed)
        self.hibp_toggle.toggled.connect(self._on_hibp_toggled)
        self.history_button.clicked.connect(self._open_history_dialog)
        self.save_history_button.clicked.connect(self._save_to_history)

        for box in (
            self.check_uppercase,
            self.check_lowercase,
            self.check_digits,
            self.check_symbols,
            self.check_exclude_ambiguous,
        ):
            box.toggled.connect(self._regenerate)
        self.words_spin.valueChanged.connect(self._regenerate)

    def _on_mode_changed(self) -> None:
        is_characters = self.mode_characters.isChecked()
        self.words_spin.setEnabled(not is_characters)
        for box in (
            self.check_uppercase,
            self.check_lowercase,
            self.check_digits,
            self.check_symbols,
            self.check_exclude_ambiguous,
        ):
            box.setEnabled(is_characters)
        self._regenerate()

    def _on_hibp_toggled(self, checked: bool) -> None:
        if checked and self._current_password:
            self._run_hibp_check(self._current_password)
        else:
            self._set_status("LISTO", "")

    # -- generation -----------------------------------------------------

    def _regenerate(self) -> None:
        if self.mode_characters.isChecked():
            options = GeneratorOptions(
                use_uppercase=self.check_uppercase.isChecked(),
                use_lowercase=self.check_lowercase.isChecked(),
                use_digits=self.check_digits.isChecked(),
                use_symbols=self.check_symbols.isChecked(),
                exclude_ambiguous=self.check_exclude_ambiguous.isChecked(),
            )
            pools = options.active_pools()
            if not pools:
                self.readout.setText("SELECCIONA AL MENOS UNA CATEGORIA DE CARACTERES")
                self.meter.set_ratio(0.0)
                self.entropy_value.setText("0.0 bits")
                self.entropy_rating.setText("-")
                self._current_password = ""
                return
            try:
                self._current_password = generate_password(options)
            except ValueError as exc:
                self.readout.setText(str(exc).upper())
                self._current_password = ""
                return
            pool_size = len("".join(pools))
            rating = entropy.bits_from_pool(pool_size, PASSWORD_LENGTH)
        else:
            word_count = self.words_spin.value()
            self._current_password = passphrase.generate_passphrase(word_count=word_count)
            rating = entropy.bits_from_wordlist(passphrase.wordlist_size(), word_count)

        self.readout.setText(self._current_password)
        self._update_entropy_display(rating)
        self._set_status("LISTO", "")

        if self.hibp_toggle.isChecked():
            self._run_hibp_check(self._current_password)

    def _update_entropy_display(self, rating: entropy.EntropyRating) -> None:
        self.entropy_value.setText(f"{rating.bits:.1f} bits")
        self.entropy_rating.setText(rating.label.upper())
        ratio = min(rating.bits / _MAX_MEANINGFUL_BITS, 1.0)
        self.meter.set_ratio(ratio)

    # -- actions ----------------------------------------------------------

    def _copy_current(self) -> None:
        if not self._current_password:
            return
        clipboard: QClipboard = QApplication.clipboard()
        clipboard.setText(self._current_password)
        self._flash_copy_button()

    def _flash_copy_button(self) -> None:
        original = self.copy_button.text()
        self.copy_button.setText("COPIADO")
        self.copy_button.setStyleSheet("border: 1px solid #6FCF97; color: #6FCF97;")

        def _restore():
            self.copy_button.setText(original)
            self.copy_button.setStyleSheet("")

        from PySide6.QtCore import QTimer

        QTimer.singleShot(900, _restore)

    def _run_hibp_check(self, password: str) -> None:
        self._set_status("CONSULTANDO HIBP...", "warn")
        self._hibp_worker = HibpWorker(password)
        self._hibp_worker.finished_with_result.connect(self._on_hibp_result)
        self._hibp_worker.start()

    def _on_hibp_result(self, result: hibp.PwnedResult) -> None:
        if result.error:
            self._set_status(f"FALLO AL CONSULTAR HIBP: {result.error}", "warn")
        elif result.is_pwned:
            self._set_status(
                f"EXPUESTA - VISTA {result.times_seen}x EN FILTRACIONES CONOCIDAS", "danger"
            )
        else:
            self._set_status("SIN COINCIDENCIAS EN FILTRACIONES CONOCIDAS", "ok")

    def _set_status(self, text: str, state: str) -> None:
        self.status_strip.setText(text)
        self.status_strip.setProperty("state", state)
        self.status_strip.style().unpolish(self.status_strip)
        self.status_strip.style().polish(self.status_strip)

    # -- history / vault ----------------------------------------------------

    def _open_history_dialog(self) -> None:
        dialog = HistoryDialog(Vault(), self)
        dialog.exec()

    def _prompt_master_password(self, confirm: bool) -> str | None:
        master, ok = QInputDialog.getText(
            self, "Contrasena maestra", "Contrasena maestra del historial:", QLineEdit.Password
        )
        if not ok or not master:
            return None

        if confirm:
            repeated, ok2 = QInputDialog.getText(
                self,
                "Confirmar contrasena maestra",
                "El historial no existe todavia. Repite la contrasena maestra:",
                QLineEdit.Password,
            )
            if not ok2 or repeated != master:
                self._set_status("LAS CONTRASENAS MAESTRAS NO COINCIDEN", "danger")
                return None

        return master

    def _save_to_history(self) -> None:
        if not self._current_password:
            return

        site = self.site_input.text().strip()
        if not site:
            self._set_status("INDICA UN SITIO PARA GUARDAR EN EL HISTORIAL", "warn")
            return
        username = self.user_input.text().strip()

        vault = Vault()
        master = self._prompt_master_password(confirm=not vault.exists())
        if master is None:
            return

        mode = "passphrase" if self.mode_passphrase.isChecked() else "password"
        try:
            bits = float(self.entropy_value.text().split()[0])
        except (ValueError, IndexError):
            bits = 0.0
        label = self.entropy_rating.text().lower()

        try:
            vault.add_entry(
                master,
                site=site,
                username=username,
                password=self._current_password,
                bits=bits,
                label=label,
                mode=mode,
            )
        except WrongMasterPassword:
            self._set_status("CONTRASENA MAESTRA INCORRECTA", "danger")
            return

        self._set_status(f"GUARDADO EN HISTORIAL ({site})", "ok")
        self.site_input.clear()
        self.user_input.clear()


def run() -> None:
    app = QApplication.instance() or QApplication([])
    _load_fonts()

    style_path = resources.files("atalaya.gui").joinpath("style.qss")
    with resources.as_file(style_path) as path:
        app.setStyleSheet(path.read_text(encoding="utf-8"))

    window = MainWindow()
    window.show()
    app.exec()


if __name__ == "__main__":
    run()
