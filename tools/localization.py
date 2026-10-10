"""NS-105 offline Qt extraction, catalog validation and test pseudo tooling."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
from string import Formatter
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / 'translations/netsentinel_en.ts'
EXCEPTIONS = ROOT / 'docs/localization/literal-exceptions.json'
SOURCES = [ROOT / 'src/netsentinel/presentation', ROOT / 'src/netsentinel/shared/source_text.py']
SOURCES.append(ROOT / 'src/netsentinel/shared/enum_sources.py')
SOURCES += [ROOT / f'src/netsentinel/application/services/{name}.py' for name in
            ('baseline_detail', 'risk_explanation', 'incident_timeline', 'response_ui',
             'threat_intel_evidence', 'mark_normal')]
SINKS = {'setText', 'setWindowTitle', 'setAccessibleName', 'setAccessibleDescription',
         'setToolTip', 'setPlaceholderText', 'QLabel', 'QPushButton', 'QCheckBox',
         'QGroupBox', 'addMenu', 'addAction', 'addTab', 'addItem', 'setPlainText'}


def fields(text: str) -> Counter[tuple[str, str, str | None]]:
    result = Counter((field, spec or '', conversion) for _, field, spec, conversion
                     in Formatter().parse(text) if field is not None)
    if any(not key.isidentifier() or '{' in spec or '}' in spec or
           conversion not in (None, 's', 'r', 'a') for key, spec, conversion in result):
        raise ValueError('only simple named placeholders are allowed')
    return result


def keys(path: Path) -> set[tuple[str, str, str, bool]]:
    tree = ET.parse(path)
    result = set()
    for context in tree.findall('context'):
        for message in context.findall('message'):
            translation = message.find('translation')
            if translation is None or translation.get('type', '') not in ('obsolete', 'vanished'):
                result.add((context.findtext('name', ''), message.findtext('source', ''),
                    message.findtext('comment', ''), message.get('numerus') == 'yes'))
    return result


def validate(path: Path, *, finished: bool = False) -> None:
    root = ET.parse(path).getroot()
    seen = set()
    for context in root.findall('context'):
        context_name = context.findtext('name')
        if not context_name:
            raise ValueError('translation context required')
        for message in context.findall('message'):
            source = message.findtext('source', '')
            key = (context_name, source, message.findtext('comment', ''))
            if key in seen:
                raise ValueError('duplicate translation key')
            seen.add(key)
            expected = fields(source)
            translation = message.find('translation')
            if translation is None or translation.get('type') == 'unfinished':
                if finished:
                    raise ValueError('unfinished translation')
                continue
            if translation.get('type') in ('obsolete', 'vanished'):
                if finished:
                    raise ValueError('obsolete translation')
                continue
            forms = translation.findall('numerusform') if message.get('numerus') == 'yes' else [translation]
            if not forms:
                raise ValueError('numerus forms required')
            # Current fixtures are English. Production locale form acceptance
            # (including linguistic review) belongs to NS-107, not this source gate.
            if message.get('numerus') == 'yes' and root.get('language', '').startswith('en') and len(forms) != 2:
                raise ValueError('English numerus requires two Qt forms')
            for form in forms:
                target = form.text or ''
                if not target or fields(target) != expected or target.count('%n') != source.count('%n'):
                    raise ValueError('empty translation or changed placeholders/numerus')
                if target.count('{{') != source.count('{{') or target.count('}}') != source.count('}}'):
                    raise ValueError('changed escaped braces')


def extract(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, '-m', 'PyQt6.lupdate.pylupdate', '--no-obsolete',
                    '--no-summary', '--ts', str(output), *map(str, SOURCES)], cwd=ROOT, check=True)
    root = ET.parse(output).getroot()
    root.set('sourcelanguage', 'en_US')
    root.set('language', 'en_US')
    contexts = sorted(root.findall('context'), key=lambda c: c.findtext('name', ''))
    for context in contexts:
        root.remove(context)
        messages = sorted(context.findall('message'), key=lambda m: (m.findtext('source', ''), m.findtext('comment', '')))
        for message in messages:
            context.remove(message)
            for location in message.findall('location'):
                # Source locations stay relative to the canonical catalog,
                # independent of checkout/temp output directory and line churn.
                location_path = (output.parent / location.get('filename', '')).resolve()
                location.set('filename', '../' + location_path.relative_to(ROOT).as_posix())
                location.attrib.pop('line', None)
            context.append(message)
        root.append(context)
    ET.indent(root, space='  ')
    ET.ElementTree(root).write(output, encoding='utf-8', xml_declaration=True)
    validate(output)


def literals() -> set[tuple[str, str]]:
    """Bounded literal/prose scan. No claim of complete data-flow analysis."""
    found = set()
    for source in SOURCES:
        for path in sorted(source.rglob('*.py')) if source.is_dir() else [source]:
            if path.name in ('text.py', 'manager.py', '__init__.py') and 'i18n' in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'))
            parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                value = node.value
                parent = parents.get(node)
                chain = []
                ancestor = parent
                while ancestor:
                    chain.append(ancestor)
                    ancestor = parents.get(ancestor)
                calls = [item for item in chain if isinstance(item, ast.Call)]
                names = [c.func.attr if isinstance(c.func, ast.Attribute) else c.func.id
                         if isinstance(c.func, ast.Name) else '' for c in calls]
                if 'translate' in names or 'QT_TRANSLATE_NOOP' in names:
                    continue
                if isinstance(parent, ast.Expr) or any(isinstance(p, (ast.Raise, ast.ImportFrom, ast.Import)) for p in chain):
                    continue
                if isinstance(parent, ast.Dict) and node in parent.keys:
                    continue
                if isinstance(parent, ast.Subscript) and node is parent.slice:
                    continue
                # Catch direct UI sink literals as well as prose in intermediate
                # tuples/defaults. Technical exceptions are exact, reviewed pairs.
                if set(names) & SINKS or re.search(r'[A-Za-z].*\s+[A-Za-z]', value):
                    found.add((path.relative_to(ROOT).as_posix(), value))
    return found


def check() -> None:
    validate(CATALOG)
    with tempfile.TemporaryDirectory(dir=ROOT / 'build', prefix='i18n-check-') as temporary:
        output = Path(temporary) / 'source.ts'
        extract(output)
        if keys(output) != keys(CATALOG):
            raise ValueError('source catalog out of date; run extract')
    baseline = json.loads(EXCEPTIONS.read_text(encoding='utf-8'))
    allowed = {(item['file'], item['source']) for item in baseline}
    missing = literals() - allowed
    stale = allowed - literals()
    if missing or stale:
        raise ValueError('unreviewed or stale literal exceptions: ' + repr(sorted(missing or stale)[:10]))
    catalog_keys = keys(CATALOG)
    print(f'Localization PASS: {len(catalog_keys)} strings, {len({k[0] for k in catalog_keys})} contexts, '
          f'{sum(k[3] for k in catalog_keys)} numerus keys, {len(allowed)} reviewed literal exceptions')


def verify_resources(root: Path) -> None:
    """Wheel/frozen build must contain exactly the allowlisted catalog inventory."""
    from hashlib import sha256
    from netsentinel.presentation.i18n.manager import PLANNED_LOCALES, MAX_CATALOG_BYTES
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    if not isinstance(manifest, dict) or manifest.get('version') != 1 or not isinstance(manifest.get('catalogs'), dict):
        raise ValueError('invalid catalog manifest')
    planned = {item.id for item in PLANNED_LOCALES} - {'en'}
    if not set(manifest['catalogs']) <= planned:
        raise ValueError('unallowlisted locale')
    expected = {f'netsentinel_{locale}.qm' for locale in manifest['catalogs']}
    if {path.name for path in root.glob('*.qm')} != expected:
        raise ValueError('catalog package inventory mismatch')
    for locale, entry in manifest['catalogs'].items():
        data = (root / f'netsentinel_{locale}.qm').read_bytes()
        if not 0 < len(data) <= MAX_CATALOG_BYTES or sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('catalog resource digest/size mismatch')


def pseudo(output: Path) -> None:
    root = ET.parse(CATALOG).getroot()
    for context in root.findall('context'):
        for message in context.findall('message'):
            source = message.findtext('source', '')
            translation = message.find('translation')
            if translation is not None:
                message.remove(translation)
            translation = ET.SubElement(message, 'translation')
            # Accent only literal parts, retaining every placeholder byte/type.
            pieces = []
            for literal, field, spec, conversion in Formatter().parse(source):
                pieces.append(literal.replace('{', '{{').replace('}', '}}').translate(str.maketrans('aeiouAEIOU', 'àëïøüÀËÏØÜ')))
                if field is not None:
                    pieces.append('{' + field + ('!' + conversion if conversion else '') + (':' + spec if spec else '') + '}')
            text = '[!! ' + ''.join(pieces) + ' expanded !!]'
            if message.get('numerus') == 'yes':
                for _ in range(2):
                    ET.SubElement(translation, 'numerusform').text = text
            else:
                translation.text = text
    output.parent.mkdir(parents=True, exist_ok=True)
    ET.indent(root, space='  ')
    ET.ElementTree(root).write(output, encoding='utf-8', xml_declaration=True)
    validate(output, finished=True)


def compile_catalog(catalog: Path, output: Path, compiler: Path) -> None:
    validate(catalog, finished=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(compiler.resolve()), '-nounfinished', str(catalog.resolve()),
                    '-qm', str(output.resolve())], check=True, cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('extract', 'check', 'pseudo', 'compile'))
    parser.add_argument('--catalog', type=Path, default=CATALOG)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--lrelease', type=Path, default=ROOT / 'build/i18n-tools/PySide6/lrelease.exe')
    args = parser.parse_args()
    (ROOT / 'build').mkdir(exist_ok=True)
    if args.command == 'extract':
        extract(args.output or CATALOG)
    elif args.command == 'check':
        check()
        verify_resources(ROOT / 'src/netsentinel/assets/i18n')
    elif args.command == 'pseudo':
        pseudo(args.output or ROOT / 'build/i18n/pseudo.ts')
    else:
        if args.output is None:
            parser.error('compile requires --output (no implicit production catalog)')
        compile_catalog(args.catalog, args.output, args.lrelease)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
