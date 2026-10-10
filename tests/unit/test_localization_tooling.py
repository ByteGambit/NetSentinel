"""NS-105 extraction/validation and package contracts, all offline."""

import ast
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

import pytest

from tools import localization as tool
from netsentinel.presentation.i18n import manager as loader
from netsentinel.presentation.i18n.text import placeholders, render_text
from netsentinel.shared.source_text import QT_TRANSLATE_NOOP, SourceText, join_text

FIXTURE = Path(__file__).parents[1] / 'fixtures/i18n'


def test_real_fixture_placeholders_and_numerus():
    tool.validate(FIXTURE / 'pseudo.ts', finished=True)
    assert sum(key[3] for key in tool.keys(FIXTURE / 'pseudo.ts')) == 3


@pytest.mark.parametrize('source, target', [
    ('Value {count:d}', 'Value {renamed:d}'),
    ('Value {count:d}', 'Value {count:s}'),
    ('Value {count} {count}', 'Value {count}'),
    ('Value {count!r}', 'Value {count!s}'),
    ('Value {{literal}} {count}', 'Value {count}'),
    ('%n records', 'records'),
    ('Value {count}', ''),
])
def test_catalog_validation_rejects_missing_renamed_typed_escaped_parameters(tmp_path, source, target):
    root = ET.Element('TS', version='2.1', language='en_US')
    context = ET.SubElement(root, 'context')
    ET.SubElement(context, 'name').text = 'Fixture'
    message = ET.SubElement(context, 'message')
    ET.SubElement(message, 'source').text = source
    ET.SubElement(message, 'translation').text = target
    path = tmp_path / 'invalid.ts'
    ET.ElementTree(root).write(path, encoding='utf-8')
    with pytest.raises(ValueError):
        tool.validate(path, finished=True)


@pytest.mark.parametrize('template', ['{value.attribute}', '{value[0]}', '{value:{width}}', '{0}'])
def test_no_evaluated_or_nested_placeholders(template):
    with pytest.raises(ValueError):
        placeholders(template)
    with pytest.raises(ValueError):
        tool.fields(template)


def test_extraction_source_catalog_and_bounded_literal_gate():
    tool.check()
    catalog_keys = tool.keys(tool.CATALOG)
    assert len(catalog_keys) > 1000
    assert any(key[0] == 'StandardButtons' for key in catalog_keys)
    assert any(key[0] == 'ResponseUi' for key in catalog_keys)
    assert any(key[3] and '%n' in key[1] for key in catalog_keys)


def test_new_literal_sink_is_detected(tmp_path, monkeypatch):
    source = tmp_path / 'view.py'
    source.write_text('label.setText("New untranslated warning.")\nlabel.setObjectName("stable_id")\n', encoding='utf-8')
    monkeypatch.setattr(tool, 'ROOT', tmp_path)
    monkeypatch.setattr(tool, 'SOURCES', [source])
    assert tool.literals() == {('view.py', 'New untranslated warning.')}


def test_domain_application_never_import_qt_translation():
    root = tool.ROOT / 'src/netsentinel'
    for directory in ('domain', 'application', 'shared'):
        for path in (root / directory).rglob('*.py'):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    assert not (node.module or '').startswith(('PyQt', 'PySide', 'netsentinel.presentation'))
                elif isinstance(node, ast.Import):
                    assert all(not item.name.startswith(('PyQt', 'PySide')) for item in node.names)


def test_raw_canonical_descriptors_join_and_bound_without_qt(qapp):
    from copy import deepcopy
    message = QT_TRANSLATE_NOOP('Fixture', 'Value {value}').format(value='192.0.2.1')
    assert isinstance(message, SourceText)
    assert message == 'Value 192.0.2.1'
    combined = join_text('\n', (message, 'raw.example.'))
    assert render_text(combined) == str(combined)
    assert render_text(message.bounded(4)) == 'Valu… [display truncated]'
    assert render_text('raw.example.') == 'raw.example.'
    assert deepcopy(message).parts == message.parts
    with pytest.raises(AttributeError):
        message.parts = ()
    with pytest.raises(AttributeError):
        del message.maximum


def manifest_resource(tmp_path, data):
    root = tmp_path / 'i18n'
    root.mkdir()
    (root / 'netsentinel_tr.qm').write_bytes(data)
    manifest = {'version': 1, 'catalogs': {'tr': {'sha256': sha256(data).hexdigest()}}}
    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return root, manifest


def test_bundled_only_loader_digest_inventory_and_package_layout(tmp_path, monkeypatch):
    data = (FIXTURE / 'pseudo.qm').read_bytes()
    root, manifest = manifest_resource(tmp_path, data)
    monkeypatch.setattr(loader.resources, 'files', lambda _: tmp_path)
    assert loader.bundled_catalog('tr') == data
    assert loader.bundled_catalog('de') is None
    tool.verify_resources(root)
    (root / 'netsentinel_tr.qm').write_bytes(data + b'corruption')
    with pytest.raises(ValueError):
        loader.bundled_catalog('tr')
    with pytest.raises(ValueError):
        tool.verify_resources(root)
    manifest['catalogs']['../../external'] = manifest['catalogs'].pop('tr')
    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    with pytest.raises(ValueError):
        tool.verify_resources(root)


@pytest.mark.parametrize('manifest', ['[]', '{"version": 99, "catalogs": {}}', '{"version": 1, "catalogs": []}', 'x' * 16385])
def test_invalid_resource_manifest_is_rejected(tmp_path, monkeypatch, manifest):
    root = tmp_path / 'i18n'
    root.mkdir()
    (root / 'manifest.json').write_text(manifest, encoding='utf-8')
    monkeypatch.setattr(loader.resources, 'files', lambda _: tmp_path)
    with pytest.raises(ValueError):
        loader.bundled_catalog('tr')


def test_package_inventory_is_english_only_and_schema_020():
    root = tool.ROOT / 'src/netsentinel/assets/i18n'
    tool.verify_resources(root)
    assert json.loads((root / 'manifest.json').read_text(encoding='utf-8'))['catalogs'] == {}
    assert not list(root.glob('*.qm'))
    schema = sorted((tool.ROOT / 'src/netsentinel/infrastructure/sqlite/schema').glob('*.sql'))
    assert [int(path.name[:3]) for path in schema] == list(range(1, 21))
    pyproject = (tool.ROOT / 'pyproject.toml').read_text(encoding='utf-8')
    spec = (tool.ROOT / 'packaging/NetSentinel.spec').read_text(encoding='utf-8')
    assert 'assets/i18n/*.qm' in pyproject
    assert 'i18n.glob("*.qm")' in spec


def test_compiler_invocation_excludes_unfinished_and_is_offline(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, 'run', lambda args, **kwargs: calls.append((args, kwargs)))
    tool.compile_catalog(FIXTURE / 'pseudo.ts', tmp_path / 'fixture.qm', tmp_path / 'lrelease.exe')
    assert calls[0][0][1] == '-nounfinished'
    assert calls[0][0][-2] == '-qm'
    assert calls[0][1]['check'] is True


def test_source_catalog_cannot_be_shipped_as_fake_finished_english(tmp_path):
    with pytest.raises(ValueError, match='unfinished'):
        tool.compile_catalog(tool.CATALOG, tmp_path / 'fake.qm', tmp_path / 'lrelease.exe')


def test_complete_pseudo_catalog_has_exact_source_keys_and_placeholders(tmp_path):
    path = tmp_path / 'pseudo.ts'
    tool.pseudo(path)
    assert tool.keys(path) == tool.keys(tool.CATALOG)
    tool.validate(path, finished=True)
