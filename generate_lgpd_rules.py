#!/usr/bin/env python3
"""
generate_lgpd_rules.py
Gera local_rules_lgpd.xml com overrides adicionando mapeamentos LGPD
às regras nativas do Wazuh que possuem tags GDPR.

Uso:
    python3 generate_lgpd_rules.py \
        --rules-dir /var/ossec/ruleset/rules \
        --output /var/ossec/etc/rules/local_rules_lgpd.xml
"""

import argparse
import copy
import glob
import os
import sys
import xml.etree.ElementTree as ET

GDPR_TO_LGPD = {
    "gdpr_II_5.1.f":  "lgpd_Art6_VII",
    "gdpr_IV_30.1.g": "lgpd_Art37",
    "gdpr_IV_32.2":   "lgpd_Art46",
    "gdpr_IV_35.7.d": "lgpd_Art38",
}

LGPD_ARTICLES = {
    "lgpd_Art6_VII": "Art. 6, VII  — Princípio da segurança (integridade e confidencialidade)",
    "lgpd_Art37":    "Art. 37      — Registro das operações de tratamento de dados pessoais",
    "lgpd_Art46":    "Art. 46      — Medidas de segurança técnicas e administrativas no tratamento",
    "lgpd_Art38":    "Art. 38      — Relatório de Impacto à Proteção de Dados Pessoais (RIPD)",
}

GDPR_ARTICLES = {
    "gdpr_II_5.1.f":  "Art. 5(1)(f) — Integridade e confidencialidade",
    "gdpr_IV_30.1.g": "Art. 30(1)(g) — Registro das atividades de tratamento",
    "gdpr_IV_32.2":   "Art. 32(2)   — Segurança no tratamento",
    "gdpr_IV_35.7.d": "Art. 35(7)(d) — DPIA / Avaliação de impacto",
}


def get_lgpd_tags(groups_text: str) -> list:
    seen = set()
    result = []
    for gdpr_tag, lgpd_tag in GDPR_TO_LGPD.items():
        if gdpr_tag in groups_text and lgpd_tag not in seen:
            result.append(lgpd_tag)
            seen.add(lgpd_tag)
    return result


def indent_xml(elem: ET.Element, level: int = 0) -> None:
    """Adiciona indentação ao XML (compatível com Python < 3.9)."""
    pad = "\n" + "  " * level
    pad_child = "\n" + "  " * (level + 1)
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = pad_child
        if not elem.tail or not elem.tail.strip():
            elem.tail = pad
        for child in elem:
            indent_xml(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = pad
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = pad
        if not elem.text:
            pass


def resolve_vars(text: str, vars_dict: dict) -> str:
    for name, val in vars_dict.items():
        text = text.replace(f"${name}", val)
    return text


def build_override(rule_el: ET.Element, lgpd_tags: list,
                   vars_dict: dict | None = None) -> ET.Element:
    override = ET.Element("rule")
    for attr, val in rule_el.attrib.items():
        resolved = resolve_vars(val, vars_dict or {})
        override.set(attr, resolved)
    override.set("overwrite", "yes")

    group_el = rule_el.find("group")
    groups_text = (group_el.text or "").strip() if group_el is not None else ""

    for child in rule_el:
        if child.tag != "group":
            override.append(copy.deepcopy(child))

    new_group = ET.SubElement(override, "group")
    base = groups_text.rstrip(",")
    if base:
        new_group.text = base + "," + ",".join(lgpd_tags) + ","
    else:
        new_group.text = ",".join(lgpd_tags) + ","

    return override


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules-dir",
                        default="/var/ossec/ruleset/rules",
                        help="Diretório das regras nativas do Wazuh (padrão: /var/ossec/ruleset/rules)")
    parser.add_argument("--output",
                        default="/var/ossec/etc/rules/local_rules_lgpd.xml",
                        help="Caminho do arquivo de saída")
    parser.add_argument("--min-level", type=int, default=0,
                        help="Nível mínimo das regras a incluir (padrão: 0 = todas)")
    parser.add_argument("--exclude-files", nargs="*", default=["0215-policy_rules.xml"],
                        help="Arquivos de regras a excluir (mesmos do rule_exclude no ossec.conf)")
    args = parser.parse_args()

    if not os.path.isdir(args.rules_dir):
        print(f"ERRO: Diretório não encontrado: {args.rules_dir}", file=sys.stderr)
        sys.exit(1)

    root = ET.Element("group")
    root.set("name", "lgpd,")

    total = 0
    stats = {tag: 0 for tag in GDPR_TO_LGPD.values()}
    processed_files = 0

    exclude_set = set(args.exclude_files or [])

    for xml_path in sorted(glob.glob(os.path.join(args.rules_dir, "*.xml"))):
        if os.path.basename(xml_path) in exclude_set:
            print(f"INFO: Excluindo {os.path.basename(xml_path)} (rule_exclude)", file=sys.stderr)
            continue
        try:
            # Wazuh rule files can have multiple root <group> elements (invalid XML).
            # Wrap in a dummy root before parsing.
            with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
            wrapped = f"<_root_>{raw}</_root_>"
            tree = ET.ElementTree(ET.fromstring(wrapped))
        except ET.ParseError as e:
            print(f"WARN: Ignorando {os.path.basename(xml_path)}: {e}", file=sys.stderr)
            continue

        # Coletar variáveis definidas no arquivo (<var name="X">val</var>)
        vars_dict = {}
        for var_el in tree.getroot().iter("var"):
            vname = var_el.get("name", "").strip()
            vval = (var_el.text or "").strip()
            if vname and vval:
                vars_dict[vname] = vval

        file_overrides = []
        for rule in tree.getroot().iter("rule"):
            rule_level = int(rule.get("level", 0))
            if rule_level < args.min_level:
                continue

            group_el = rule.find("group")
            groups_text = (group_el.text or "") if group_el is not None else ""

            lgpd_tags = get_lgpd_tags(groups_text)
            if not lgpd_tags:
                continue

            override = build_override(rule, lgpd_tags, vars_dict)
            file_overrides.append(override)
            for tag in lgpd_tags:
                stats[tag] += 1
            total += 1

        if file_overrides:
            processed_files += 1
            marker = ET.SubElement(root, "_comment_")
            marker.set("value", f" {os.path.basename(xml_path)} — {len(file_overrides)} regra(s) ")
            for override in file_overrides:
                # Indentar o elemento antes de adicionar
                if hasattr(ET, "indent"):
                    ET.indent(override, space="  ", level=1)
                root.append(override)

    if total == 0:
        print("Nenhuma regra com tags GDPR encontrada.", file=sys.stderr)
        sys.exit(1)

    # Serializar manualmente para preservar comentários e encoding
    lines = ['<!--',
             '  LGPD Compliance Overrides — Wazuh',
             '  Lei Geral de Proteção de Dados (Lei 13.709/2018)',
             '  Gerado por: generate_lgpd_rules.py',
             '  ',
             '  Mapeamento GDPR → LGPD:']
    for gdpr_tag, lgpd_tag in GDPR_TO_LGPD.items():
        g_desc = GDPR_ARTICLES[gdpr_tag]
        l_desc = LGPD_ARTICLES[lgpd_tag]
        lines.append(f'    GDPR {g_desc}')
        lines.append(f'    LGPD {l_desc}')
        lines.append(f'    Tag: {gdpr_tag} → {lgpd_tag}  ({stats[lgpd_tag]} regras)')
        lines.append('  ')
    lines.append(f'  Total: {total} regras com override LGPD em {processed_files} arquivo(s).')
    lines.append('-->')
    lines.append('')
    lines.append('<group name="lgpd,">')
    lines.append('')

    current_comment = None
    indent = "  "

    for child in root:
        if child.tag == "_comment_":
            comment_val = child.get("value", "")
            lines.append(f'{indent}<!-- {comment_val}-->')
            continue

        # Serializar a regra com indentação
        rule_str = ET.tostring(child, encoding="unicode")
        # Indentar cada linha da regra
        for line in rule_str.split("\n"):
            if line.strip():
                lines.append(f"{indent}{line.strip()}")
        lines.append("")

    lines.append("</group>")
    lines.append("")

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Gerado: {args.output}")
    print(f"Total de regras com override LGPD: {total} em {processed_files} arquivo(s)")
    print("")
    for gdpr_tag, lgpd_tag in GDPR_TO_LGPD.items():
        print(f"  {lgpd_tag:20s}  {stats[lgpd_tag]:4d} regras  ← {gdpr_tag}")


if __name__ == "__main__":
    main()
