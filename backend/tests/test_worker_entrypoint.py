"""Exercise the production -m entrypoint without starting its infinite queue loop."""
import subprocess
import sys
from pathlib import Path


def test_module_entrypoint_shares_queue_owner_and_exceptions():
    script = '''
import runpy
import sys

class EnteredMain(Exception):
    pass

def at_main(frame, event, arg):
    spec = frame.f_globals.get('__spec__')
    if event == 'call' and frame.f_code.co_name == 'main' and getattr(spec, 'name', None) == 'app.worker':
        from app import worker
        assert worker.__dict__ is frame.f_globals, 'entrypoint created a second worker owner'
        assert worker.WORKER_ID == frame.f_globals['WORKER_ID']
        assert worker.JobNoLongerActive is frame.f_globals['JobNoLongerActive']
        raise EnteredMain
    return at_main

sys.settrace(at_main)
try:
    runpy.run_module('app.worker', run_name='__main__', alter_sys=True)
except EnteredMain:
    print('ENTRYPOINT_OK')
finally:
    sys.settrace(None)
'''
    result = subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).resolve().parents[1],
                            text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert 'ENTRYPOINT_OK' in result.stdout
