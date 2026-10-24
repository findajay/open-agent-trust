"""Regenerate docs/images/demo-terminal.svg, the animated terminal in the README.

The lines mirror real `oat demo` and `oat proof verify` output (key ids shortened, one
long line trimmed). Run after changing what the demo prints:

    uv run python scripts/make_readme_terminal.py
"""

from __future__ import annotations

from html import escape
from pathlib import Path

OUT = Path(__file__).parents[1] / "docs" / "images" / "demo-terminal.svg"

CYCLE = 20.0  # seconds for both scenes, then it loops
WIDTH, TOP, LINE, LEFT, CHAR = 960, 62, 21, 28, 7.82

Segments = list[tuple[str, str]]


def out(text: str, cls: str = "o") -> Segments:
    return [(cls, text)]


def action(name: str, resource: str, effect: str, status: str, receipt: str) -> Segments:
    effect_cls = {"allow": "g", "require_approval": "y", "deny": "r"}[effect]
    status_cls = "g" if status == "succeeded" else "d"
    return [
        ("o", f"   {name:<13} {resource:<22} "),
        (effect_cls, f"{effect:<17} "),
        (status_cls, f"{status:<13} "),
        ("d", receipt),
    ]


def check(status: str, name: str, detail: str) -> Segments:
    return [
        ("o", "   "),
        ("g" if status == "pass" else "r", f"[{status}]"),
        ("o", f" {name}: "),
        ("d", detail),
    ]


# (show at, hide at, typed?, segments)
SCENE_1 = 11.5
SCENE_2 = 19.4
LINES: list[tuple[float, float, bool, Segments]] = [
    (0.2, SCENE_1, True, [("p", "$ "), ("c", "uv run oat demo")]),
    (1.4, SCENE_1, False, out("1. Identities", "h")),
    (1.6, SCENE_1, False, out("   acme-industries    ed25519:9SJgrgkH8u2IEpyh...", "d")),
    (1.7, SCENE_1, False, out("   planner-agent      ed25519:dNTuv4TaNXOPiqaM...", "d")),
    (1.8, SCENE_1, False, out("   maintenance-agent  ed25519:xSfHjoQjWOezfzy1...", "d")),
    (1.9, SCENE_1, False, out("   shift-supervisor   ed25519:pKL6zUv-XZMs1_lf...", "d")),
    (2.0, SCENE_1, False, out("   plant-7-gateway    ed25519:qxcFfPS5B5M-CkSh...", "d")),
    (
        2.5,
        SCENE_1,
        False,
        out("2. Delegation: acme-industries -> planner-agent -> maintenance-agent", "h"),
    ),
    (
        3.0,
        SCENE_1,
        False,
        out("3. Policy: read freely, restart needs a supervisor, never delete logs", "h"),
    ),
    (3.5, SCENE_1, False, out("4. Agent actions through the gateway", "h")),
    (
        4.1,
        SCENE_1,
        False,
        action("sensor.read", "plant-7/pump/P-3", "allow", "succeeded", "01-sensor.read.json"),
    ),
    (
        4.8,
        SCENE_1,
        False,
        action(
            "pump.restart",
            "plant-7/pump/P-3",
            "require_approval",
            "succeeded",
            "02-pump.restart.json",
        ),
    ),
    (
        5.5,
        SCENE_1,
        False,
        action(
            "logs.delete", "plant-7/logs/2026-10", "deny", "not_executed", "03-logs.delete.json"
        ),
    ),
    (
        6.2,
        SCENE_1,
        False,
        [
            ("o", f"   {'pump.restart':<13} {'plant-9/pump/P-1':<22} "),
            ("r", "REJECTED  "),
            ("d", "no receipt (delegation link 0 does not permit ...)"),
        ],
    ),
    (7.0, SCENE_1, False, out("5. Independent verification", "h")),
    (7.5, SCENE_1, False, check("pass", "ledger", "3 receipts, chain intact")),
    (
        8.2,
        SCENE_1,
        False,
        out("   tampered copy of the denied receipt (outcome rewritten to 'succeeded'):", "o"),
    ),
    (8.6, SCENE_1, False, check("fail", "gateway-signature", "receipt signature is not valid")),
    (8.9, SCENE_1, False, check("fail", "enforcement", "a denied request was executed")),
    (
        12.0,
        SCENE_2,
        True,
        [
            ("p", "$ "),
            (
                "c",
                "oat proof verify receipts/02-pump.restart.json --trust trust.json --policy policy.yaml",
            ),
        ],
    ),
]
VERIFY_CHECKS = [
    ("structure", "valid agentproof.receipt/v0.1"),
    ("gateway-trusted", "issued by a trusted gateway"),
    ("gateway-signature", "receipt signature valid"),
    ("request-digest", "request_digest matches the embedded request"),
    ("agent-signature", "request signed by the agent"),
    ("timing", "receipt issued after the request"),
    ("delegation-chain", "2-link chain from a trust anchor to the agent"),
    ("delegation-scope", "every link permits the action and resource"),
    ("policy-decision", "policy reproduces 'require_approval'"),
    ("approval", "approved by an authorised approver"),
    ("enforcement", "outcome 'succeeded' respects the decision"),
]


def pct(seconds: float) -> str:
    return f"{100 * seconds / CYCLE:.2f}%"


def build() -> str:
    lines = list(LINES)
    for index, (name, detail) in enumerate(VERIFY_CHECKS):
        segments = check("pass", name, detail)
        segments[0] = ("o", "")
        lines.append((13.6 + 0.17 * index, SCENE_2, False, segments))
    lines.append((15.8, SCENE_2, False, out("VERIFIED", "v")))

    rows_scene_1 = sum(1 for show, *_ in lines if show < SCENE_1)
    rows = max(rows_scene_1, len(lines) - rows_scene_1)
    height = TOP + rows * LINE + 24
    css, body = [], []
    row = {SCENE_1: 0, SCENE_2: 0}
    for index, (show, hide, typed, segments) in enumerate(lines):
        y = TOP + row[hide] * LINE
        row[hide] += 1
        css.append(
            f"@keyframes l{index} {{ 0%, {pct(show)} {{ opacity: 0; }} "
            f"{pct(show + 0.05)}, {pct(hide)} {{ opacity: 1; }} {pct(hide + 0.2)}, 100% {{ opacity: 0; }} }}"
            f" .l{index} {{ animation: l{index} {CYCLE}s linear infinite; }}"
        )
        spans = "".join(f'<tspan class="{cls}">{escape(text)}</tspan>' for cls, text in segments)
        scene = "s1" if hide == SCENE_1 else "s2"
        body.append(
            f'<text class="t l{index} {scene}" x="{LEFT}" y="{y}" xml:space="preserve">{spans}</text>'
        )
        if typed:
            prompt = len(segments[0][1])
            chars = sum(len(text) for _, text in segments) - prompt
            start, end = show + 0.2, show + 0.2 + min(1.6, 0.035 * chars)
            x = LEFT + prompt * CHAR
            width = chars * CHAR + 10
            # The cover is only visible while its own line is: scenes share rows, so a
            # cover left in place would hide the other scene's line.
            css.append(
                f"@keyframes k{index} {{ 0%, {pct(show)} {{ visibility: hidden; transform: translateX(0); }} "
                f"{pct(show + 0.01)}, {pct(start)} {{ visibility: visible; transform: translateX(0); }} "
                f"{pct(end)}, {pct(hide)} {{ visibility: visible; transform: translateX({width:.0f}px); }} "
                f"{pct(hide + 0.01)}, 100% {{ visibility: hidden; transform: translateX({width:.0f}px); }} }}"
                f" .k{index} {{ animation: k{index} {CYCLE}s steps(40, end) infinite; }}"
            )
            body.append(
                f'<rect class="cover k{index}" x="{x:.0f}" y="{y - 15}" width="{width:.0f}" height="20"/>'
            )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" height="{height}" role="img" aria-labelledby="t d">
  <title id="t">oat demo</title>
  <desc id="d">Terminal recording: oat demo runs four agent actions through the gateway (allowed, approved, denied, rejected), verifies the ledger and catches a tampered receipt; then oat proof verify checks one receipt and prints VERIFIED.</desc>
  <!-- Generated by scripts/make_readme_terminal.py. Do not edit by hand. -->
  <style>
    .win {{ fill: #0d1117; stroke: #30363d; }}
    .bar {{ fill: #161b22; }}
    .cover {{ fill: #0d1117; }}
    .t {{ font: 13px ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; opacity: 0; }}
    .ttl {{ font: 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #8b949e; }}
    .o {{ fill: #c9d1d9; }} .d {{ fill: #8b949e; }} .h {{ fill: #f0f6fc; font-weight: 700; }}
    .p {{ fill: #34d399; font-weight: 700; }} .c {{ fill: #f0f6fc; }}
    .g {{ fill: #34d399; }} .y {{ fill: #fbbf24; }} .r {{ fill: #f87171; }}
    .v {{ fill: #34d399; font-weight: 700; }}
    {chr(10).join("    " + rule for rule in css).strip()}
    @media (prefers-reduced-motion: reduce) {{
      .t {{ animation: none !important; opacity: 1; }} .cover, .s2 {{ display: none; }}
    }}
  </style>
  <rect class="win" x="0.5" y="0.5" width="{WIDTH - 1}" height="{height - 1}" rx="12"/>
  <path class="bar" d="M12.5 0.5 H{WIDTH - 12.5} A12 12 0 0 1 {WIDTH - 0.5} 12.5 V34 H0.5 V12.5 A12 12 0 0 1 12.5 0.5 Z"/>
  <circle cx="22" cy="17" r="6" fill="#ff5f57"/><circle cx="42" cy="17" r="6" fill="#febc2e"/><circle cx="62" cy="17" r="6" fill="#28c840"/>
  <text class="ttl" x="{WIDTH / 2:.0f}" y="21" text-anchor="middle">open-agent-trust: zsh</text>
  {chr(10).join("  " + line for line in body).strip()}
</svg>
"""


def main() -> None:
    OUT.write_text(build(), encoding="utf-8", newline="\n")
    print(OUT)


if __name__ == "__main__":
    main()
