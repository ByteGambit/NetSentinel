"""Explicit NS-080 storage operations, without automatic policy creation."""

from datetime import datetime
from uuid import UUID, uuid4

from netsentinel.application.ports import ScopedPreferenceRepository
from netsentinel.domain.preferences import (
    PreferenceDefinition, PreferenceMatchContext, PreferenceOrigin, PreferencePage, PreferenceResult,
)


class ScopedPreferenceService:
    """Blocking port facade for future command workers; no clock or Qt dependency."""

    def __init__(self, repository: ScopedPreferenceRepository) -> None:
        self._repository = repository

    def create(self, definition: PreferenceDefinition, *, origin: PreferenceOrigin,
               now: datetime, preference_id: UUID | None = None, deduplicate: bool = False) -> PreferenceResult:
        # Caller may retain an ID for idempotent command retries.
        identity = preference_id if preference_id is not None else uuid4()
        if deduplicate:
            return self._repository.create(identity, definition, origin, now, deduplicate=True)
        return self._repository.create(identity, definition, origin, now)

    def edit(self, preference_id: UUID, definition: PreferenceDefinition, *,
             expected_revision: int, origin: PreferenceOrigin, now: datetime) -> PreferenceResult:
        return self._repository.edit(preference_id, expected_revision, definition, origin, now)

    def revoke(self, preference_id: UUID, *, expected_revision: int, reason: str,
               origin: PreferenceOrigin, now: datetime) -> PreferenceResult:
        return self._repository.revoke(preference_id, expected_revision, reason, origin, now)

    def get_current(self, preference_id: UUID) -> PreferenceResult:
        return self._repository.get_current(preference_id)

    def get_history(self, preference_id: UUID, *, limit: int = 32,
                    before_revision: int | None = None) -> PreferencePage:
        return self._repository.get_history(preference_id, limit=limit, before_revision=before_revision)

    def list_current(self, *, limit: int = 100, after_id: UUID | None = None) -> PreferencePage:
        return self._repository.list_current(limit=limit, after_id=after_id)

    def find_candidates(self, contexts: tuple[PreferenceMatchContext, ...], *,
                        evaluated_at: datetime, limit: int = 32) -> PreferencePage:
        return self._repository.find_candidates(contexts, evaluated_at=evaluated_at, limit=limit)
