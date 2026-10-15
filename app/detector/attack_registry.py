"""
attack_registry.py
------------------
Saldırı dedektörlerinin kayıt (plugin) sistemi.

Nasıl çalışır?
  - `detector/attacks/` klasöründeki tüm Python modülleri otomatik olarak import edilir.
  - Bir sınıf `@register` dekoratörüyle işaretlenirse registery'e eklenir.
  - `get_all_detectors()` kayıtlı tüm dedektör örneklerini döner.

Yeni bir saldırı tipi eklemek için:
  1. `detector/attacks/yeni_saldiri.py` dosyası oluştur.
  2. `BaseAttackDetector`'dan türet, `detect()` ve `confidence()` implement et.
  3. Sınıf tanımının üstüne `@register` dekoratörü ekle.
  4. Başka hiçbir şeye dokunmana gerek yok — sistem otomatik bulup yükler.
"""

import importlib
import pkgutil
import detector.attacks as _attacks_pkg
from typing import Type, List
from detector.base_attack import BaseAttackDetector

_registry: dict[str, Type[BaseAttackDetector]] = {}


def register(cls: Type[BaseAttackDetector]) -> Type[BaseAttackDetector]:
    """
    Sınıfı saldırı kayıt defterine ekleyen dekoratör.

    Kullanım:
        @register
        class DosDetector(BaseAttackDetector):
            ...
    """
    if not issubclass(cls, BaseAttackDetector):
        raise TypeError(f"{cls.__name__} BaseAttackDetector'dan türemek zorunda.")
    _registry[cls.name] = cls
    return cls


def _auto_load_attacks() -> None:
    """
    `detector/attacks/` içindeki tüm modülleri import ederek
    `@register` dekoratörlü sınıfların yüklenmesini tetikler.
    """
    pkg_path = _attacks_pkg.__path__
    pkg_name = _attacks_pkg.__name__
    for _, module_name, _ in pkgutil.iter_modules(pkg_path):
        full_name = f"{pkg_name}.{module_name}"
        importlib.import_module(full_name)


def get_all_detectors() -> List[BaseAttackDetector]:
    """
    Kayıtlı tüm dedektörlerin örneklerini döner.
    İlk çağrıda `attacks/` klasörünü otomatik yükler.
    """
    if not _registry:
        _auto_load_attacks()
    return [cls() for cls in _registry.values()]


def list_registered() -> List[str]:
    """Kayıtlı dedektörlerin isimlerini döner."""
    if not _registry:
        _auto_load_attacks()
    return list(_registry.keys())
