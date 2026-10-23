from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Iterable
import hashlib, json, re


def norm(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    return str(value).strip().upper().replace(" ", "_") or "UNKNOWN"


def key_norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def stable_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )


@dataclass(slots=True)
class Node:
    id: str
    type: str = "UNKNOWN"
    properties: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.properties:
            return self.properties[key]
        wanted = key_norm(key)
        for actual, value in self.properties.items():
            if key_norm(actual) == wanted:
                return value
        return default

    @property
    def name(self) -> str:
        for k in (
            "name",
            "NAME",
            "fullName",
            "FULL_NAME",
            "methodFullName",
            "METHOD_FULL_NAME",
            "code",
            "CODE",
        ):
            v = self.get(k)
            if v not in (None, ""):
                return str(v)
        return ""


@dataclass(slots=True)
class Edge:
    source: str
    target: str
    type: str = "UNKNOWN"
    properties: dict[str, Any] = field(default_factory=dict)
    id: str | None = None


@dataclass(slots=True)
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    metadata: dict[str, Any] = field(
        default_factory=lambda: {"completeness": "declared", "parse_health": "OK"}
    )
    _out: dict[str, list[Edge]] = field(default_factory=dict, repr=False)
    _in: dict[str, list[Edge]] = field(default_factory=dict, repr=False)

    def add_node(self, node: Node) -> None:
        node.id = str(node.id)
        self.nodes[node.id] = node
        self._out.setdefault(node.id, [])
        self._in.setdefault(node.id, [])

    def add_edge(self, edge: Edge) -> None:
        edge.source, edge.target = str(edge.source), str(edge.target)
        self.edges.append(edge)
        self._out.setdefault(edge.source, []).append(edge)
        self._in.setdefault(edge.target, []).append(edge)

    def outgoing(self, node_id: str, edge_types: set[str] | None = None) -> list[Edge]:
        es = self._out.get(str(node_id), [])
        return (
            list(es)
            if edge_types is None
            else [e for e in es if norm(e.type) in edge_types]
        )

    def incoming(self, node_id: str, edge_types: set[str] | None = None) -> list[Edge]:
        es = self._in.get(str(node_id), [])
        return (
            list(es)
            if edge_types is None
            else [e for e in es if norm(e.type) in edge_types]
        )

    def edge_exists(
        self,
        src: str,
        dst: str,
        edge_types: set[str] | None = None,
        undirected: bool = False,
    ) -> bool:
        for e in self.outgoing(src, edge_types):
            if e.target == str(dst):
                return True
        if undirected:
            for e in self.outgoing(dst, edge_types):
                if e.target == str(src):
                    return True
        return False

    def matching_edges(
        self,
        src: str,
        dst: str,
        edge_types: set[str] | None = None,
        undirected: bool = False,
    ) -> list[Edge]:
        out = [e for e in self.outgoing(src, edge_types) if e.target == str(dst)]
        if undirected:
            out += [e for e in self.outgoing(dst, edge_types) if e.target == str(src)]
        return out

    def find_paths(
        self,
        starts: Iterable[str],
        ends: set[str],
        edge_types: set[str] | None,
        max_hops: int = 12,
        direction: str = "out",
        limit: int = 100,
        allow_cycles: bool = False,
        max_states: int | None = 50_000,
    ) -> list[list[str]]:
        paths, _ = self.find_paths_bounded(
            starts,
            ends,
            edge_types,
            max_hops=max_hops,
            direction=direction,
            limit=limit,
            allow_cycles=allow_cycles,
            max_states=max_states,
        )
        return paths

    def find_paths_bounded(
        self,
        starts: Iterable[str],
        ends: set[str],
        edge_types: set[str] | None,
        max_hops: int = 12,
        direction: str = "out",
        limit: int = 100,
        allow_cycles: bool = False,
        max_states: int | None = 50_000,
    ) -> tuple[list[list[str]], bool]:
        paths, truncated, _ = self.find_paths_bounded_detailed(
            starts,
            ends,
            edge_types,
            max_hops=max_hops,
            direction=direction,
            limit=limit,
            allow_cycles=allow_cycles,
            max_states=max_states,
        )
        return paths, truncated

    def find_paths_bounded_detailed(
        self,
        starts: Iterable[str],
        ends: set[str],
        edge_types: set[str] | None,
        max_hops: int = 12,
        direction: str = "out",
        limit: int = 100,
        allow_cycles: bool = False,
        max_states: int | None = 50_000,
        should_cancel: Any = None,
    ) -> tuple[list[list[str]], bool, int]:
        starts = sorted({str(x) for x in starts})
        ends = {str(x) for x in ends}
        result: list[list[str]] = []
        from collections import deque

        states = 0
        truncated = False
        if max_hops < 0 or limit <= 0:
            return result, False, states
        for start in starts:
            q = deque([(start, [start])])
            while q and len(result) < limit:
                if should_cancel is not None and should_cancel():
                    return result, True, states
                cur, path = q.popleft()
                states += 1
                if max_states is not None and states > int(max_states):
                    return result, True, states - 1
                depth = len(path) - 1
                if depth > 0 and cur in ends:
                    result.append(path)
                    continue
                if depth >= max_hops:
                    continue
                if direction == "out":
                    edges = self.outgoing(cur, edge_types)
                elif direction == "in":
                    edges = self.incoming(cur, edge_types)
                elif direction == "either":
                    edges = self.outgoing(cur, edge_types) + self.incoming(
                        cur, edge_types
                    )
                else:
                    return result, True, states
                edges = sorted(
                    edges,
                    key=lambda e: (
                        str(e.source),
                        str(e.target),
                        str(e.type),
                        str(e.id or ""),
                    ),
                )
                seen_next: set[str] = set()
                for edge in edges:
                    nxt = (
                        edge.target
                        if direction in {"out", "either"} and edge.source == cur
                        else edge.source
                    )
                    if nxt in seen_next:
                        continue
                    seen_next.add(nxt)
                    if not allow_cycles and nxt in path:
                        continue
                    q.append((nxt, path + [nxt]))
            if len(result) >= limit:
                if q or start != starts[-1]:
                    truncated = True
                break
        return result, truncated, states

    def summary(self) -> dict[str, Any]:
        nt, et = {}, {}
        for n in self.nodes.values():
            nt[n.type] = nt.get(n.type, 0) + 1
        for e in self.edges:
            et[e.type] = et.get(e.type, 0) + 1
        d = {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "node_types": dict(sorted(nt.items())),
            "edge_types": dict(sorted(et.items())),
        }
        for k in (
            "format",
            "parser",
            "parse_health",
            "joern_style",
            "loss_risk",
            "integrity",
            "parser_issues",
            "completeness",
            "semantic_enrichment",
            "merge_sources",
            "merge_conflicts",
        ):
            if k in self.metadata:
                d[k] = self.metadata[k]
        return d

    def detailed_summary(self, sample_limit: int = 20) -> dict[str, Any]:
        d = self.summary()
        d["node_property_keys"] = sorted(
            {str(k) for n in self.nodes.values() for k in n.properties}
        )
        d["edge_property_keys"] = sorted(
            {str(k) for e in self.edges for k in e.properties}
        )
        d["node_samples"] = [
            {"id": n.id, "type": n.type, "properties": n.properties}
            for n in list(self.nodes.values())[:sample_limit]
        ]
        d["edge_samples"] = [
            {
                "id": e.id,
                "source": e.source,
                "target": e.target,
                "type": e.type,
                "properties": e.properties,
            }
            for e in self.edges[:sample_limit]
        ]
        return d

    def digest(self) -> str:
        h = hashlib.sha256()
        for n in sorted(self.nodes.values(), key=lambda x: x.id):
            h.update(f"N|{n.id}|{n.type}|{stable_json(n.properties)}\n".encode())
        for e in sorted(
            self.edges, key=lambda x: (x.source, x.target, x.type, x.id or "")
        ):
            h.update(
                f"E|{e.id}|{e.source}|{e.target}|{e.type}|{stable_json(e.properties)}\n".encode()
            )
        return h.hexdigest()
