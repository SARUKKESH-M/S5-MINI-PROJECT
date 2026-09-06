"""Stage 7A deterministic AST security evidence regression coverage."""

from ast_engine.security_analyzer import analyze_security_structure


def _signals(source: str):
    return analyze_security_structure(source, file_path="sample.py")["security_signals"]


def test_parameterized_sql_is_not_sql_injection_evidence():
    signals = _signals('def get(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))')
    assert not [signal for signal in signals if signal["category"] == "sql_injection"]


def test_dynamic_sql_concatenation_and_f_string_are_detected():
    concat = _signals('def get(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
    fstring = _signals('def get(cursor, user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")')
    assert concat[0]["signal_type"] == "unsafe_database_execution"
    assert concat[0]["severity"] == "high"
    assert fstring[0]["signal_type"] == "unsafe_database_execution"


def test_command_execution_distinguishes_shell_and_argument_vector():
    fixed = _signals('def run():\n    os.system("date")')
    dynamic = _signals('def run(user_input):\n    os.system(user_input)')
    safe_vector = _signals('def run():\n    subprocess.run(["git", "status"], shell=False)')
    assert fixed[0]["severity"] == "medium"
    assert dynamic[0]["severity"] == "critical"
    assert safe_vector[0]["argument_assessment"]["shell"] is False
    assert safe_vector[0]["severity"] == "medium"


def test_dynamic_execution_and_hardcoded_secret_remain_detected():
    signals = _signals('def run(user_input):\n    api_key = "not-a-real-secret"\n    eval(user_input)\n    exec(user_input)')
    assert sum(signal["signal_type"] == "dynamic_code_execution" for signal in signals) == 2
    assert all(signal["severity"] == "critical" for signal in signals if signal["signal_type"] == "dynamic_code_execution")
    assert any(signal["signal_type"] == "possible_hardcoded_secret" for signal in signals)


def test_credential_flow_to_authorization_header_is_medium():
    signals = _signals('def headers(auth_token):\n    api_key = auth_token\n    return {"Authorization": f"Bearer {api_key}"}')
    flow = [signal for signal in signals if signal["signal_type"] == "credential_propagation_to_authorization_sink"]
    assert len(flow) == 1
    assert flow[0]["severity"] == "medium"
    assert flow[0]["file_path"] == "sample.py"
    assert len(flow[0]["evidence_id"]) == 64


# ===========================================================================
# Phase 20: Path Traversal / Unsafe File Access Positive & Negative Tests
# ===========================================================================

def test_path_traversal_string_concatenation_detected():
    signals = _signals('def read_file(filename):\n    open("/uploads/" + filename)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1
    assert pt[0]["severity"] == "high"
    assert pt[0]["confidence"] == "high"


def test_path_traversal_f_string_detected():
    signals = _signals('def read_file(user_path):\n    open(f"data/{user_path}")')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1
    assert pt[0]["severity"] == "high"
    assert pt[0]["confidence"] == "high"


def test_path_traversal_dynamic_variable_detected():
    signals = _signals('def read_file(user_path):\n    open(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1
    assert pt[0]["severity"] == "medium"
    assert pt[0]["confidence"] == "medium"


def test_path_traversal_io_open_detected():
    signals = _signals('import io\ndef read_file(user_path):\n    io.open(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_os_open_detected():
    signals = _signals('import os\ndef read_file(user_path):\n    os.open(user_path, os.O_RDONLY)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_os_remove_detected():
    signals = _signals('import os\ndef del_file(user_path):\n    os.remove(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_os_unlink_detected():
    signals = _signals('import os\ndef del_file(user_path):\n    os.unlink(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_os_rmdir_detected():
    signals = _signals('import os\ndef del_dir(user_path):\n    os.rmdir(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_shutil_rmtree_detected():
    signals = _signals('import shutil\ndef del_tree(user_path):\n    shutil.rmtree(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_path_open_detected():
    signals = _signals('from pathlib import Path\ndef read_file(user_path):\n    Path.open(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_pathlib_path_open_detected():
    signals = _signals('import pathlib\ndef read_file(user_path):\n    pathlib.Path.open(user_path)')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_static_literal_is_safe():
    signals = _signals('def read_config():\n    open("config.json", "r")')
    assert not [s for s in signals if s["signal_type"] == "path_traversal_call"]


def test_path_traversal_static_absolute_is_safe():
    signals = _signals('def read_hosts():\n    open("/etc/hosts")')
    assert not [s for s in signals if s["signal_type"] == "path_traversal_call"]


def test_path_traversal_static_os_remove_is_safe():
    signals = _signals('import os\ndef clean():\n    os.remove("temp.lock")')
    assert not [s for s in signals if s["signal_type"] == "path_traversal_call"]


def test_path_traversal_static_path_open_is_safe():
    signals = _signals('from pathlib import Path\ndef read_cfg():\n    Path.open("config.txt")')
    assert not [s for s in signals if s["signal_type"] == "path_traversal_call"]


def test_path_traversal_open_path_dynamic_detected():
    signals = _signals('from pathlib import Path\ndef read_file(user_path):\n    open(Path(user_path))')
    pt = [s for s in signals if s["signal_type"] == "path_traversal_call"]
    assert len(pt) == 1


def test_path_traversal_receiver_read_text_is_out_of_scope():
    signals = _signals('def read_file(p):\n    p.read_text()')
    assert not [s for s in signals if s["signal_type"] == "path_traversal_call"]


def test_path_traversal_path_division_is_not_file_call():
    signals = _signals('from pathlib import Path\ndef get_path(base, user_input):\n    return Path(base) / user_input')
    assert not [s for s in signals if s["signal_type"] == "path_traversal_call"]


# ===========================================================================
# Phase 20: Insecure Deserialization Positive & Negative Tests
# ===========================================================================

def test_insecure_deserialization_pickle_loads_detected():
    signals = _signals('import pickle\ndef load_data(user_data):\n    pickle.loads(user_data)')
    deser = [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]
    assert len(deser) == 1
    assert deser[0]["severity"] == "critical"
    assert deser[0]["confidence"] == "high"


def test_insecure_deserialization_pickle_load_detected():
    signals = _signals('import pickle\ndef load_file(file_obj):\n    pickle.load(file_obj)')
    deser = [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]
    assert len(deser) == 1
    assert deser[0]["severity"] == "critical"
    assert deser[0]["confidence"] == "high"


def test_insecure_deserialization_underscore_pickle_loads_detected():
    signals = _signals('import _pickle\ndef load_data(user_data):\n    _pickle.loads(user_data)')
    deser = [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]
    assert len(deser) == 1


def test_insecure_deserialization_underscore_pickle_load_detected():
    signals = _signals('import _pickle\ndef load_file(file_obj):\n    _pickle.load(file_obj)')
    deser = [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]
    assert len(deser) == 1


def test_insecure_deserialization_cpickle_loads_detected():
    signals = _signals('import cPickle\ndef load_data(user_data):\n    cPickle.loads(user_data)')
    deser = [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]
    assert len(deser) == 1


def test_insecure_deserialization_cpickle_load_detected():
    signals = _signals('import cPickle\ndef load_file(file_obj):\n    cPickle.load(file_obj)')
    deser = [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]
    assert len(deser) == 1


def test_deserialization_json_loads_is_safe():
    signals = _signals('import json\ndef load_data(user_data):\n    json.loads(user_data)')
    assert not [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]


def test_deserialization_json_load_is_safe():
    signals = _signals('import json\ndef load_file(file_obj):\n    json.load(file_obj)')
    assert not [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]


def test_deserialization_yaml_safe_load_is_safe():
    signals = _signals('import yaml\ndef load_data(user_data):\n    yaml.safe_load(user_data)')
    assert not [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]


def test_deserialization_service_loads_is_safe():
    signals = _signals('def handle(service, user_data):\n    service.loads(user_data)')
    assert not [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]


def test_shelve_open_is_not_flagged_by_deserialization():
    signals = _signals('import shelve\ndef open_db():\n    shelve.open("database.db")')
    assert not [s for s in signals if s["signal_type"] == "insecure_deserialization_call"]
    assert not [s for s in signals if s["signal_type"] == "path_traversal_call"]
