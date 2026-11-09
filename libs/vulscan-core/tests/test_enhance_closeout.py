"""轮数用尽或工具参数坏掉后，单次补充分类的行为。"""
import utilities.context_enhancer as ce
from utilities.context_enhancer import ContextEnhancer


class _Binding:
    phase = "enhance"
    model = "fake-model"


def _enhancer():
    return ContextEnhancer(binding=_Binding(), tracker=object())


def _unit():
    return {"id": "a.py:f", "code": {"primary_code": "eval(user_input)"}}


def test_closeout_returns_real_classification(monkeypatch):
    monkeypatch.setattr(ce, "simple_text", lambda *a, **k: (
        '{"security_classification":"exploitable",'
        '"classification_reasoning":"外部输入进入 eval","confidence":0.7}'))
    ctx = _enhancer()._closeout_single_shot(_unit())
    assert ctx["security_classification"] == "exploitable"
    assert ctx["closeout"] == "fallback_single_shot"
    assert ctx["confidence"] == 0.7


def test_closeout_rejects_unknown_label(monkeypatch):
    monkeypatch.setattr(ce, "simple_text", lambda *a, **k: (
        '{"security_classification":"totally_made_up",'
        '"classification_reasoning":"x","confidence":0.5}'))
    ctx = _enhancer()._closeout_single_shot(_unit())
    assert ctx["security_classification"] == "unknown"


def test_closeout_returns_none_without_json(monkeypatch):
    monkeypatch.setattr(ce, "simple_text", lambda *a, **k: "I cannot answer")
    assert _enhancer()._closeout_single_shot(_unit()) is None


def test_closeout_returns_none_without_code():
    assert _enhancer()._closeout_single_shot({"id": "empty"}) is None
