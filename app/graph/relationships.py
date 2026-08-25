"""Graph-based relationship analysis for campaign clustering and attribution."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select

from app.db.models import Case, Indicator
from app.db.session import get_session


@dataclass
class Relationship:
    """Connection between two cases via shared infrastructure."""

    case_a: UUID
    case_b: UUID
    shared_indicators: list[dict]  # [{"kind": "ip", "value": "1.2.3.4"}]
    strength: float  # 0-1, based on number/importance of shared indicators
    distance: int  # graph distance (1 = direct connection)


@dataclass
class CampaignCluster:
    """A group of related cases connected via shared infrastructure."""

    cluster_id: str
    cases: list[UUID]
    core_indicators: dict[str, set[str]]  # kind -> set of values
    relationships: list[Relationship]
    size: int
    score: float  # Cohesion score based on connection strength


def _find_shared_indicators(case_a: UUID, case_b: UUID, session) -> list[dict]:
    """Find all indicators shared between two cases."""
    stmt_a = select(Indicator).where(Indicator.case_id == case_a)
    indicators_a = {(ind.kind, ind.value) for ind in session.execute(stmt_a).scalars()}

    stmt_b = select(Indicator).where(Indicator.case_id == case_b)
    indicators_b = {(ind.kind, ind.value) for ind in session.execute(stmt_b).scalars()}

    shared = indicators_a & indicators_b
    return [{"kind": k, "value": v} for k, v in shared]


def _calculate_relationship_strength(shared_indicators: list[dict]) -> float:
    """Score relationship strength: IP=0.8, domain=0.6, url=0.4, hash=0.3."""
    weights = {"ip": 0.8, "urlreg": 0.5, "url": 0.4, "hash": 0.3}
    total_weight = sum(weights.get(ind["kind"], 0.1) for ind in shared_indicators)
    return min(1.0, total_weight / 2.0)  # Cap at 1.0


def build_campaign_graph(max_distance: int = 3) -> dict[str, CampaignCluster]:
    """Build graph of related cases and return campaign clusters."""
    session = get_session()
    try:
        # Get all cases
        all_cases = session.execute(select(Case.id)).scalars().all()
        if not all_cases:
            return {}

        # Build direct connections (distance=1)
        connections: dict[UUID, list[tuple[UUID, Relationship]]] = defaultdict(list)
        for case_a in all_cases:
            for case_b in all_cases:
                if case_a >= case_b:  # Avoid duplicates
                    continue
                shared = _find_shared_indicators(case_a, case_b, session)
                if shared:
                    strength = _calculate_relationship_strength(shared)
                    rel = Relationship(
                        case_a=case_a,
                        case_b=case_b,
                        shared_indicators=shared,
                        strength=strength,
                        distance=1,
                    )
                    connections[case_a].append((case_b, rel))
                    connections[case_b].append((case_a, rel))

        # BFS to find transitive connections and build clusters
        clusters: dict[str, CampaignCluster] = {}
        visited: set[UUID] = set()
        cluster_id = 0

        for start_case in all_cases:
            if start_case in visited:
                continue

            # BFS from this case
            queue = deque([(start_case, 0)])
            cluster_cases: set[UUID] = set()
            cluster_relationships: list[Relationship] = []
            cluster_indicators: dict[str, set[str]] = defaultdict(set)

            while queue:
                current, dist = queue.popleft()
                if current in visited or dist > max_distance:
                    continue

                visited.add(current)
                cluster_cases.add(current)

                # Add current case's indicators
                stmt = select(Indicator).where(Indicator.case_id == current)
                for ind in session.execute(stmt).scalars():
                    cluster_indicators[ind.kind].add(ind.value)

                # Explore neighbors
                for neighbor, rel in connections[current]:
                    if neighbor not in visited:
                        cluster_relationships.append(rel)
                        queue.append((neighbor, dist + 1))

            # Create cluster if it has multiple cases
            if len(cluster_cases) > 1:
                cluster_score = sum(r.strength for r in cluster_relationships) / max(
                    len(cluster_relationships), 1
                )
                cluster = CampaignCluster(
                    cluster_id=f"campaign_{cluster_id}",
                    cases=sorted(cluster_cases, key=str),
                    core_indicators=dict(cluster_indicators),
                    relationships=cluster_relationships,
                    size=len(cluster_cases),
                    score=cluster_score,
                )
                clusters[cluster.cluster_id] = cluster
                cluster_id += 1

        return clusters
    finally:
        session.close()


def get_case_relationships(case_id: UUID) -> dict:
    """Get all relationships for a specific case."""
    session = get_session()
    try:
        relationships = []
        stmt = select(Case.id).limit(100)  # Reasonable limit
        all_cases = session.execute(stmt).scalars().all()

        for other_case in all_cases:
            if other_case == case_id:
                continue
            shared = _find_shared_indicators(case_id, other_case, session)
            if shared:
                strength = _calculate_relationship_strength(shared)
                relationships.append(
                    {
                        "case_id": str(other_case),
                        "shared_indicators": shared,
                        "strength": strength,
                    }
                )

        return {
            "case_id": str(case_id),
            "related_count": len(relationships),
            "relationships": sorted(
                relationships, key=lambda x: x["strength"], reverse=True
            )[:5],  # Top 5
        }
    finally:
        session.close()
