#!/usr/bin/env python3
"""Opt-in real historical handler/compiler regression; retains rejection logs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import mcp_compiler_adapter as adapter
import mcp_fixture_contract as fixtures


class HistoricalCompilerRegression(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('MCP_COMPILER_ADAPTER_EVIDENCE'),
                         'set MCP_COMPILER_ADAPTER_EVIDENCE to a new retained directory')
    def test_real_generator_compiler_and_invalid_cache_rejection(self):
        output=Path(os.environ['MCP_COMPILER_ADAPTER_EVIDENCE']).resolve()
        output.mkdir(parents=True,exist_ok=False)
        def invoke(name):
            with patch.object(sys,'argv',['mcp_fixture_contract.py','--generator',
                                          'execute-with-secret','--output',str(output/name)]):
                fixtures.main()
        # Synthetic ambient sentinels must not reach the actual filtered child;
        # inherited compiler overrides must not replace the resolved compiler.
        noise={'AWS_SESSION_TOKEN':'adapter-synthetic-sentinel',
               'HTTPS_PROXY':'http://invalid.invalid', 'SSH_AUTH_SOCK':'synthetic',
               'GOFLAGS':'-overlay=does-not-exist.json','GOOS':'windows','GOARCH':'386'}
        with patch.dict(os.environ,noise):
            invoke('positive')
        receipt=json.loads((output/'positive/receipt.json').read_bytes())
        self.assertTrue(receipt['passed'])
        for lane in receipt['lanes']:
            self.assertEqual((lane['fixtures'],lane['cases']),(1,13))
            self.assertTrue(lane['compiler_adapter']['verified'])
            self.assertEqual(lane['steps'][-1]['executed_tests'],['TestGenerateMCPExecuteWithSecretFixture'])
        original_prepare=adapter.prepare
        def invalid_cache(go,env,tree,out,steps,run_step):
            isolated,row=original_prepare(go,env,tree,out,steps,run_step)
            # Mutate only the separately compiled preparation, not historical
            # generator/product/fixture bytes. The real Go compiler rejects it.
            config=copy.deepcopy(row['configuration'])
            config['environment']['GOCACHE']='relative-invalid-cache'
            (out/'config.go').write_text('package main\n\nconst configJSON = '+json.dumps(json.dumps(config,sort_keys=True))+'\n')
            command=steps[-2]['command']
            run_step(command,out,row['build_environment'],out,'negative-build',steps)
            row.update(configuration=config,
                       source_inputs=fixtures.inventory(out,row['source_inputs']),
                       binary_sha256=hashlib.sha256(Path(row['binary']).read_bytes()).hexdigest())
            (out/'mutation.json').write_text(json.dumps(row,indent=2)+'\n')
            return isolated,row
        with patch.object(adapter,'prepare',side_effect=invalid_cache), self.assertRaisesRegex(RuntimeError,'generators failed'):
            invoke('invalid-cache')
        rejected=json.loads((output/'invalid-cache/receipt.json').read_bytes())
        self.assertFalse(rejected['passed'])
        lane=rejected['lanes'][0]
        self.assertEqual(lane['steps'][-1]['exit'],1)
        log=(output/'invalid-cache/historical/generators.stdout').read_text()
        self.assertIn('--- FAIL: TestGenerateMCPExecuteWithSecretFixture',log)
        self.assertIn('execute_with_secret fixture stale',log)
        call=json.loads(Path(lane['compiler_adapter']['configuration']['trace']).read_text())
        self.assertNotEqual(call['exit'],0)
        self.assertEqual(call['command'][0],lane['compiler_adapter']['configuration']['compiler'])
        fixtures.fixture_anchor(fixtures.ROOT,[*fixtures.FIXTURES,*fixtures.generator_paths()])


if __name__=='__main__':
    unittest.main()
