"""Inspect the built PE resources and exercise the actual frozen scan worker."""
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import pefile

for name in ('AntiOS', 'AntiOS-GUI', 'AntiOS-Guard'):
    executable = Path('dist') / name / (name + '.exe')
    pe = pefile.PE(str(executable))
    values = {}
    for group in pe.FileInfo:
        for item in group:
            for table in getattr(item, 'StringTable', []):
                values.update(table.entries)
    assert values[b'CompanyName'] == b'DargonITP', values
    manifests = []
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == 24:
            for item in entry.directory.entries:
                for language in item.directory.entries:
                    data = language.data.struct
                    manifests.append(ET.fromstring(pe.get_data(data.OffsetToData, data.Size)))
    levels = [level.attrib['level'] for root in manifests
              for level in root.iter('{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel')]
    expected_level = 'requireAdministrator' if name == 'AntiOS' else 'asInvoker'
    assert levels == [expected_level], levels
    pe.close()
    with tempfile.TemporaryDirectory() as folder:
        request, events = Path(folder) / 'request.json', Path(folder) / 'events.jsonl'
        request.write_text(json.dumps({'path': str(Path('release/VERSION').resolve())}), encoding='utf-8')
        completed = subprocess.run([str(executable.resolve()), '--antios-scan-worker', str(request), str(events)],
                                   timeout=60, check=True)
        records = [json.loads(line) for line in events.read_text(encoding='utf-8').splitlines()]
        assert records[-1][0] == 'done', records
        result = [value for kind, value in records if kind == 'checkpoint'][-1]
        assert result['summary']['files_scanned'] == 1, result
        assert result['summary']['threats'] == 0, result
    print(f'{name}: DargonITP metadata, {expected_level} manifest, frozen worker OK')
