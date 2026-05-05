"""
レポート生成モジュール
脆弱性の詳細を汎用Markdownにまとめる（プログラム固有の提出形式に依存しない）

出力:
  - <target>_<timestamp>.md    : 読みやすいMarkdownレポート
  - <target>_<timestamp>.json  : 機械可読なJSONダンプ（LoRA学習データ兼用）
"""

import os
import json
from datetime import datetime
from typing import List, Optional
from schema import VulnSample, Exploitability, Severity


# ===========================
# 表示ラベル
# ===========================

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
}

EXPLOITABILITY_LABEL = {
    Exploitability.CONFIRMED:   "✅ Docker環境で実証済み",
    Exploitability.PRACTICAL:   "⚠️  実際に成立する可能性が高い",
    Exploitability.THEORETICAL: "💭 理論上の可能性",
}

SEVERITY_CVSS = {
    Severity.CRITICAL: "9.0〜10.0",
    Severity.HIGH:     "7.0〜8.9",
    Severity.MEDIUM:   "4.0〜6.9",
    Severity.LOW:      "0.1〜3.9",
}


class ReportGenerator:

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(
        self,
        samples: List[VulnSample],
        target: str,
        format: str = "markdown",
    ) -> str:
        """
        脆弱性レポートを生成してファイルに保存する

        Args:
            samples: VulnSampleのリスト（is_vulnerable=False は自動除外）
            target:  スキャン対象（URL / パスなど）
            format:  無視される（後方互換のために残している）

        Returns:
            保存されたMarkdownレポートのパス
        """
        reportable = [s for s in samples if s.label.is_vulnerable]

        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2,   Severity.LOW: 3, None: 4,
        }
        exploit_order = {
            Exploitability.CONFIRMED:   0,
            Exploitability.PRACTICAL:   1,
            Exploitability.THEORETICAL: 2,
        }
        reportable.sort(key=lambda s: (
            exploit_order.get(s.attack_model.exploitability, 2),
            severity_order.get(s.label.severity, 4),
        ))

        self._print_summary(reportable)

        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = _slugify(target)

        md_content = self._build_markdown(reportable, target)
        md_path    = os.path.join(self.output_dir, f"{target_slug}_{timestamp}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        json_path = os.path.join(self.output_dir, f"{target_slug}_{timestamp}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                [s.to_dict() for s in reportable],
                f, ensure_ascii=False, indent=2,
            )

        print(f"[+] Markdownレポート : {md_path}")
        print(f"[+] JSONデータ       : {json_path}")
        return md_path

    # ===========================
    # 内部ビルダー
    # ===========================

    def _print_summary(self, samples: List[VulnSample]) -> None:
        confirmed = sum(1 for s in samples
                        if s.attack_model.exploitability == Exploitability.CONFIRMED)
        compound  = sum(1 for s in samples
                        if s.context and s.context.is_compound)
        codeql    = sum(1 for s in samples
                        if s.context and s.context.codeql_confirmed)

        print(f"\n[+] 報告対象: {len(samples)}件  "
              f"(confirmed={confirmed}, compound={compound}, CodeQL証明={codeql})")
        for s in samples:
            sev_label = s.label.severity.value.upper() if s.label.severity else "?"
            func      = s.context.function if s.context else "?"
            badges    = []
            if s.context and s.context.codeql_confirmed: badges.append("CodeQL✓")
            if s.context and s.context.is_compound:       badges.append("複合")
            badge_str = f" [{', '.join(badges)}]" if badges else ""
            print(f"    [{sev_label}] {s.label.cwe} - {func}"
                  f"{badge_str} ({s.attack_model.exploitability.value})")

    def _build_markdown(self, samples: List[VulnSample], target: str) -> str:
        if not samples:
            return f"# Vulnerability Report\n\n**Target**: `{target}`\n\n脆弱性は検出されませんでした。\n"
        header = self._build_header(samples, target)
        toc    = self._build_toc(samples)
        body   = "\n".join(
            self._build_finding(i + 1, s) for i, s in enumerate(samples)
        )
        return header + toc + body

    def _build_header(self, samples: List[VulnSample], target: str) -> str:
        counts = {sev: 0 for sev in Severity}
        for s in samples:
            if s.label.severity:
                counts[s.label.severity] += 1

        confirmed = sum(1 for s in samples
                        if s.attack_model.exploitability == Exploitability.CONFIRMED)
        practical = sum(1 for s in samples
                        if s.attack_model.exploitability == Exploitability.PRACTICAL)

        return f"""# Vulnerability Report

| 項目 | 内容 |
|------|------|
| **Target** | `{target}` |
| **日時** | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
| **検出数** | {len(samples)} 件 |
| **🔴 Critical** | {counts[Severity.CRITICAL]} 件 |
| **🟠 High** | {counts[Severity.HIGH]} 件 |
| **🟡 Medium** | {counts[Severity.MEDIUM]} 件 |
| **🔵 Low** | {counts[Severity.LOW]} 件 |
| **実証済み (confirmed)** | {confirmed} 件 |
| **成立可能性高 (practical)** | {practical} 件 |

---

"""

    def _build_toc(self, samples: List[VulnSample]) -> str:
        lines = ["## 目次\n"]
        for i, s in enumerate(samples):
            sev_emoji = SEVERITY_EMOJI.get(s.label.severity, "⚪")
            cwe       = s.label.cwe or "Unknown"
            func      = s.context.function if s.context else "Unknown"
            anchor    = f"finding-{i+1}"
            lines.append(f"{i+1}. [{sev_emoji} {cwe} — `{func}`](#{anchor})")
        lines.append("\n---\n")
        return "\n".join(lines) + "\n"

    def _build_finding(self, index: int, s: VulnSample) -> str:
        cwe       = s.label.cwe or "Unknown"
        func      = s.context.function if s.context else "Unknown"
        file_path = s.context.file    if s.context else "Unknown"
        lang      = s.language.value

        sev_emoji = SEVERITY_EMOJI.get(s.label.severity, "⚪")
        sev_label = s.label.severity.value.upper() if s.label.severity else "UNKNOWN"
        cvss      = SEVERITY_CVSS.get(s.label.severity, "?")
        exp_label = EXPLOITABILITY_LABEL.get(s.attack_model.exploitability, "")

        badges = []
        if s.context and s.context.codeql_confirmed:
            badges.append("🔬 CodeQL Verified")
        if s.context and s.context.is_compound:
            badges.append("🔗 複合脆弱性")
        if s.attack_model.exploitability == Exploitability.CONFIRMED:
            badges.append("✅ Exploit実証済み")
        badge_line = "  ".join(badges) + "\n\n" if badges else ""

        flow_str = " → ".join(s.analysis.flow) if s.analysis.flow else "N/A"

        codeql_section = ""
        if s.context and s.context.codeql_confirmed and s.context.codeql_flow:
            flow_lines = "\n".join(f"  {line}" for line in s.context.codeql_flow[:6])
            codeql_section = f"""
#### 🔬 CodeQL Taint Flow

```
{flow_lines}
```
"""

        compound_section = ""
        if s.context and s.context.is_compound and s.context.compound_functions:
            funcs = ", ".join(f"`{f}`" for f in s.context.compound_functions)
            compound_section = f"""
#### 🔗 複合脆弱性の構成関数

この脆弱性は複数の関数が連携することで成立します: {funcs}
"""

        steps_str = "\n".join(
            f"{j+1}. {step}" for j, step in enumerate(s.attack_scenario.steps)
        )

        poc_section = ""
        if s.attack_scenario.poc_script:
            poc_section = f"""
#### PoC / Exploit

```
{s.attack_scenario.poc_script[:1500]}
```
"""

        code_section = f"```{lang}\n{s.code[:2500]}\n```"

        fix_code = (
            f"```{lang}\n{s.fix.patched_code[:1200]}\n```"
            if s.fix.patched_code
            else "_（修正コードなし）_"
        )

        return f"""---

<a id="finding-{index}"></a>
## Finding #{index}: {sev_emoji} {cwe} — `{func}`

{badge_line}| 項目 | 内容 |
|------|------|
| **Severity** | {sev_emoji} {sev_label} (CVSS {cvss}) |
| **CWE** | {cwe} |
| **Attack Type** | {s.attack_model.type.value} |
| **Exploitability** | {exp_label} |
| **ファイル** | `{file_path}` |
| **関数** | `{func}` |

### 概要

{s.reasoning.why_vulnerable}

### 影響

{s.attack_scenario.result}

### データフロー

```
Source : {s.analysis.input}
Flow   : {flow_str}
Sink   : {s.analysis.sink}
```
{codeql_section}{compound_section}
### なぜ攻撃が成立するか

{s.reasoning.why_exploitable}

### 誤検知リスク

{s.reasoning.false_positive_risk}

### 必要な前提条件

{s.attack_model.assumption}

### 再現手順

{steps_str}
{poc_section}
### 脆弱なコード

{code_section}

### 修正案

**パッチ種別**: `{s.fix.patch_type.value}`

{fix_code}

**説明**: {s.fix.explanation}

"""


def _slugify(text: str) -> str:
    """ファイル名用に文字列をサニタイズ"""
    import re
    slug = re.sub(r"[/\\:*?\"<>|]", "_", text)
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug[:60]
