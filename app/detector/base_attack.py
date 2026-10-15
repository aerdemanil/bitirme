"""
base_attack.py
--------------
Tüm saldırı dedektörlerinin uygulaması gereken soyut temel sınıf.
Yeni bir saldırı tipi eklemek için bu sınıftan türetin.
"""

from abc import ABC, abstractmethod


class BaseAttackDetector(ABC):
    """
    Bütün saldırı dedektörlerinin türediği soyut temel sınıf.
    Yeni bir saldırı dedektörü oluşturmak için:
      1. Bu sınıftan kalıtın.
      2. `name` özelliğini ve `detect()` / `confidence()` metodlarını implement edin.
      3. Sınıfı `detector/attacks/` altına yerleştirin — kayıt sistemi otomatik yükler.
    """

    # Alt sınıflar bu özelliği string olarak tanımlamalı
    name: str = "base"

    @abstractmethod
    def detect(self, features: dict) -> bool:
        """
        Verilen özellik vektörüne bakarak saldırı var mı yok mu karar verir.

        Parameters
        ----------
        features : dict
            feature_extractor.py tarafından üretilen özellik sözlüğü.

        Returns
        -------
        bool
            True  → saldırı tespit edildi
            False → normal trafik
        """
        ...

    @abstractmethod
    def confidence(self, features: dict) -> float:
        """
        Tespit için [0.0 – 1.0] arasında güven skoru döner.

        Parameters
        ----------
        features : dict
            feature_extractor.py tarafından üretilen özellik sözlüğü.

        Returns
        -------
        float
            0.0 → kesinlikle normal, 1.0 → kesinlikle saldırı
        """
        ...

    def score_breakdown(self, _features: dict) -> dict:
        """
        Kural tabanlı ve ML bazlı güven skorlarını ayrı ayrı döner.
        Alt sınıflar override etmezse sadece toplam skor döner.

        Returns
        -------
        dict
            rule_conf : float | None  — kural tabanlı skor (yoksa None)
            ml_conf   : float | None  — ML model skoru (yoksa None)
        """
        return {"rule_conf": None, "ml_conf": None}

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name='{self.name}'>"
