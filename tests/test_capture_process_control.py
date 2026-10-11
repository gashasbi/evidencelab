from pathlib import Path
import inspect
from evidencelab import capture


def test_capture_uses_process_group_for_joern_commands():
    src = inspect.getsource(capture._run)
    assert "start_new_session=True" in src
    assert "os.killpg" in src
    assert "SIGKILL" in src
