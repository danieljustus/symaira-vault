#!/usr/bin/env python3
"""Publish only numeric Winsock metadata for the two actual output servers."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

PROVIDER = 'Microsoft-Windows-Winsock-AFD'
GUID = '{e53c6823-7bb8-44bb-90dc-3f86090d48a6}'
NAMESPACE = '{http://schemas.microsoft.com/win/2004/08/events/event}'
FIELDS = frozenset(('Process', 'Endpoint', 'UserModePid', 'SocketType', 'Protocol',
                    'BufferCount', 'BufferLength', 'Port', 'Error', 'Status', 'Reason',
                    'EnterExit', 'BytesIndicated', 'BytesTransferred', 'BytesSent'))


def number(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:0[xX][0-9a-fA-F]{1,16}|-?[0-9]{1,20})', value):
        raise ValueError('invalid numeric Winsock metadata')
    result = int(value, 16 if value.lower().startswith('0x') else 10)
    if not -(1 << 63) <= result < 1 << 64:
        raise ValueError('out-of-range Winsock metadata')
    return result


def metadata(trace, receipt, summary) -> dict:
    pids = {receipt[name]['tcp-output']['server_process_id'] for name in ('go', 'rust')}
    if len(pids) != 2 or any(type(pid) is not int or not 0 < pid < 1 << 32 for pid in pids):
        raise ValueError('missing distinct output-server process IDs')
    owners, endpoints, records, seen = {}, {}, [], set()
    for _, event in ET.iterparse(trace, events=('end',)):
        if event.tag != NAMESPACE + 'Event':
            continue
        system = event.find(NAMESPACE + 'System')
        if system is None:
            event.clear()
            continue
        provider = system.find(NAMESPACE + 'Provider')
        if provider is None or not (provider.get('Name') == PROVIDER or provider.get('Guid', '').lower() == GUID):
            event.clear()
            continue
        data = {}
        for item in event.findall(NAMESPACE + 'EventData/' + NAMESPACE + 'Data'):
            key = item.get('Name')
            if key not in FIELDS:
                continue
            if key in data or len(item):
                raise ValueError('ambiguous Winsock metadata field')
            data[key] = number(item.text)
        process = data.get('Process')
        event_id = number(system.findtext(NAMESPACE + 'EventID'))
        # Microsoft AFD Event ID 1 is socket creation; field presence is not authority.
        if event_id == 1:
            if not {'Process', 'Endpoint', 'UserModePid', 'SocketType', 'Protocol'} <= data.keys():
                raise ValueError('incomplete Winsock socket-creation event')
            owners[process] = data['UserModePid']
            if owners[process] in pids:
                endpoints[process, data['Endpoint']] = len(records) + 1
        pid = owners.get(process)
        if pid not in pids:
            event.clear()
            continue
        endpoint = endpoints.get((process, data.get('Endpoint')))
        if endpoint is None:
            raise ValueError('output-server event lacks socket-creation correlation')
        created = system.find(NAMESPACE + 'TimeCreated')
        if created is None:
            raise ValueError('missing Winsock event timestamp')
        stamp = created.get('SystemTime', '')
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', stamp):
            raise ValueError('invalid Winsock event timestamp')
        datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        descriptor = dict(EventID=event_id, **{key: number(system.findtext(NAMESPACE + key))
                                             for key in ('Version', 'Level', 'Task', 'Opcode')})
        # Kernel addresses never leave the runner; creation-relative IDs retain joins.
        data.pop('Process', None)
        data.pop('Endpoint', None)
        records.append(dict(pid=pid, endpoint_id=endpoint, time=stamp, descriptor=descriptor, data=data))
        seen.add(pid)
        event.clear()
    if seen != pids:
        raise ValueError('trace lacks both actual output servers')
    losses = {}
    for key, value in re.findall(r'(?im)^\s*(Events\s*Lost|Buffers\s*Lost)\s*:\s*([0-9]+)\s*$', summary):
        key = re.sub(r'\s+', '', key).lower()
        if key in losses:
            raise ValueError('ambiguous trace-loss summary')
        losses[key] = number(value)
    return dict(provider=PROVIDER, server_pids=sorted(pids), events=records,
                loss_counts=losses,
                loss_verified=set(losses) == {'eventslost', 'bufferslost'} and not any(losses.values()),
                interpretation='Metadata only; missing/lost events or clock discontinuity invalidate timing conclusions.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw_summary = args.summary.read_bytes()
    report = metadata(args.trace, json.loads(args.receipt.read_text(encoding='utf-8')),
                      raw_summary.decode('utf-16' if raw_summary.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'))
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
