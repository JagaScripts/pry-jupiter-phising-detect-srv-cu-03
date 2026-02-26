from __future__ import annotations

import time
from typing import Any
from dataclasses import dataclass, field


@dataclass
class DraftEntry:
    """ Borrador temporal de una regla asociado a un usuario y una sesión. """
    user_id: str
    draft: dict[str, Any] = field(default_factory=dict)
    updated_at_utc: int = field(default_factory=lambda: int(time.time()))


_RULE_DRAFTS: dict[str, DraftEntry] = {}

# TTL para limpiar drafts olvidados (2h)
DRAFT_TTL_SECONDS = 2 * 60 * 60


def _now() -> int:
    return int(time.time())


def _gc() -> None:
    """ Elimina borradores caducados según el TTL configurado. """
    now = _now()
    to_delete = []
    for session_id, entry in _RULE_DRAFTS.items():
        if now - entry.updated_at_utc > DRAFT_TTL_SECONDS:
            to_delete.append(session_id)
    for sid in to_delete:
        _RULE_DRAFTS.pop(sid, None)


def get_rule_draft(session_id: str) -> dict[str, Any]:
    """
    Recupera el borrador de regla asociado a una sesión.

    Args:
        session_id (str): Identificador de la sesión.

    Returns:
        dict[str, Any]: Borrador actual de la regla o diccionario vacío.
    """
    _gc()
    entry = _RULE_DRAFTS.get(session_id)
    return entry.draft.copy() if entry else {}


def upsert_rule_draft(session_id: str, user_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    """
    Crea o actualiza el borrador de una regla para una sesión.

    Args:
        session_id (str): Identificador de la sesión.
        user_id (str): Identificador del usuario.
        patch (dict[str, Any]): Cambios parciales a aplicar al borrador.

    Returns:
        dict[str, Any]: Borrador actualizado de la regla.
    """
    _gc()
    entry = _RULE_DRAFTS.get(session_id)
    if entry is None:
        entry = DraftEntry(user_id=user_id, draft={})
        _RULE_DRAFTS[session_id] = entry

    # Seguridad básica: evita que otro user reescriba sesión
    if entry.user_id != user_id:
        raise ValueError("session_id pertenece a otro user_id")

    entry.draft.update(patch)
    entry.updated_at_utc = _now()
    return entry.draft.copy()


def clear_rule_draft(session_id: str) -> None:
    """Elimina el borrador de regla asociado a una sesión."""
    _RULE_DRAFTS.pop(session_id, None)
