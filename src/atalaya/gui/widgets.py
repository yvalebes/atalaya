"""Hand-drawn widgets for the console UI — no icon packs, no default Qt chrome."""

from __future__ import annotations

from PySide6.QtCore import QPropertyAnimation, QRectF, Qt, Property, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget

_SEGMENT_COUNT = 20
_TRACK_COLOR = QColor("#2A2E33")
_LOW_COLOR = QColor("#FF5C5C")
_MID_COLOR = QColor("#FF9E66")
_HIGH_COLOR = QColor("#4FD1C5")
_EXCELLENT_COLOR = QColor("#6FCF97")


def _color_for_ratio(ratio: float) -> QColor:
    if ratio < 0.3:
        return _LOW_COLOR
    if ratio < 0.55:
        return _MID_COLOR
    if ratio < 0.85:
        return _HIGH_COLOR
    return _EXCELLENT_COLOR


class EntropyMeter(QWidget):
    """A row of discrete segments, like a VU meter, instead of a smooth
    gradient bar — reads clearly at a glance and matches the console's
    instrument-panel language."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._ratio = 0.0
        self.setMinimumHeight(22)
        self.setMinimumWidth(220)

    def set_ratio(self, ratio: float) -> None:
        self._ratio = max(0.0, min(1.0, ratio))
        self.update()

    def paintEvent(self, event):  # noqa: N802 (Qt override)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)

        gap = 3
        count = _SEGMENT_COUNT
        total_gap = gap * (count - 1)
        segment_width = (self.width() - total_gap) / count
        lit = round(self._ratio * count)
        color = _color_for_ratio(self._ratio)

        for i in range(count):
            x = i * (segment_width + gap)
            rect = QRectF(x, 0, segment_width, self.height())
            painter.fillRect(rect, color if i < lit else _TRACK_COLOR)

        painter.end()


class ToggleSwitch(QWidget):
    """A physical-looking rocker switch used for the HIBP opt-in — deliberately
    heavier and more deliberate to click than a Material toggle, since it
    triggers a network request."""

    toggled = Signal(bool)

    def __init__(self, parent=None, accent: str = "#4FD1C5"):
        super().__init__(parent)
        self._checked = False
        self._accent = QColor(accent)
        self._knob_x = 4.0
        self.setFixedSize(46, 24)
        self.setCursor(Qt.PointingHandCursor)
        self._anim = QPropertyAnimation(self, b"knob_x")
        self._anim.setDuration(120)

    def _get_knob_x(self) -> float:
        return self._knob_x

    def _set_knob_x(self, value: float) -> None:
        self._knob_x = value
        self.update()

    knob_x = Property(float, _get_knob_x, _set_knob_x)

    def isChecked(self) -> bool:  # noqa: N802 (Qt naming convention)
        return self._checked

    def setChecked(self, value: bool) -> None:  # noqa: N802
        self._checked = value
        target = self.width() - 20 if value else 4.0
        self._anim.stop()
        self._anim.setStartValue(self._knob_x)
        self._anim.setEndValue(float(target))
        self._anim.start()

    def mousePressEvent(self, event):  # noqa: N802
        self.setChecked(not self._checked)
        self.toggled.emit(self._checked)

    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        track_color = self._accent if self._checked else QColor("#2A2E33")
        painter.setPen(Qt.NoPen)
        painter.setBrush(track_color)
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 4, 4)

        painter.setPen(QPen(QColor("#101214"), 1))
        painter.setBrush(QColor("#E4E7EB"))
        painter.drawRect(QRectF(self._knob_x, 4, 16, 16))

        painter.end()
