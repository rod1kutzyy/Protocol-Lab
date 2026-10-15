import json
import re
from collections import Counter, defaultdict
from importlib.resources import files

from jinja2 import Environment, StrictUndefined

from protocol_lab.storage.portable import rows


def markdown(value):
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#+.!|\-])", r"\\\1", text).replace("\n", "  \n")


def render_report(directory, output):
    project = None
    captures, observations, hypotheses, models, corpora, runs = [], [], [], [], [], []
    inference_runs, inference_candidates, inference_evaluations = [], [], []
    examples = defaultdict(list)
    example_counts = Counter()
    for name, row in rows(directory):
        data = row.get("metadata_json")
        if name == "projects":
            project = row
        elif name == "captures":
            captures.append(row)
        elif name == "observations":
            observations.append(data)
        elif name == "hypothesis_versions":
            hypotheses.append(data)
        elif name == "interpretation_versions":
            models.append(data)
        elif name == "corpus_versions":
            corpora.append(data)
        elif name == "validation_runs":
            runs.append(data)
        elif name == "inference_runs":
            inference_runs.append(data)
        elif name == "inference_candidates":
            inference_candidates.append(data)
        elif name == "inference_evaluations":
            inference_evaluations.append(data)
        elif name == "validation_results":
            key = (str(row["run_id"]), data["status"])
            example_counts[key] += 1
            if len(examples[key]) < 5:
                examples[key].append({**data, "packets": []})
    selected = [item for values in examples.values() for item in values if item.get("anchor")]
    for name, row in rows(directory):
        if name != "tcp_spans":
            continue
        span = row["metadata_json"]
        for item in selected:
            anchor = item["anchor"]
            r = anchor["byte_range"]
            if (
                str(row["stream_id"]) == anchor["stream_id"]
                and row["start"] < r["end"]
                and row["end"] > r["start"]
            ):
                for source in span.get("sources", []):
                    left = max(r["start"], row["start"])
                    right = min(r["end"], row["end"])
                    delta = left - row["start"]
                    item["packets"].append(
                        dict(
                            packet_id=source["packet_id"],
                            packet_index=source["packet_index"],
                            file_offset=source["file_offset"] + delta,
                            payload_start=source["packet_payload_range"]["start"] + delta,
                            length=right - left,
                        )
                    )
    env = Environment(undefined=StrictUndefined, autoescape=False, keep_trailing_newline=True)
    env.filters["md"] = markdown
    env.filters["fromjson"] = json.loads
    env.filters["pretty"] = lambda value: json.dumps(
        value, ensure_ascii=False, indent=2, default=str
    )
    template = files("protocol_lab.reports").joinpath("templates/research.md.j2").read_text()
    output.write(
        env.from_string(template).render(
            project=project,
            captures=captures,
            observations=observations,
            hypotheses=hypotheses,
            models=models,
            corpora=corpora,
            runs=runs,
            examples=examples,
            example_counts=example_counts,
            inference_runs=inference_runs,
            inference_candidates=inference_candidates,
            inference_evaluations=inference_evaluations,
        )
    )
