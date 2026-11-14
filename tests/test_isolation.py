import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

results = []
def test(fn):
    try:
        fn(); results.append((fn.__name__, "PASS", ""))
    except AssertionError as e:
        results.append((fn.__name__, "FAIL", str(e)[:300]))
    except Exception as e:
        results.append((fn.__name__, "ERROR", repr(e)[:300]))
    return fn

def kpis(html):
    """The two dashboard numbers, in order: total students, total attendance."""
    return [int(x) for x in re.findall(r'th-kpi__num" data-count="(\d+)"', html)]

@test
def dashboard_shows_only_own_students_and_attendance():
    ids = h.fresh()
    a = h.login("/faculty_login", "tch_a@x.com").get("/teacher/dashboard").get_data(as_text=True)
    b = h.login("/faculty_login", "tch_b@x.com").get("/teacher/dashboard").get_data(as_text=True)
    assert kpis(a) == [1, 2], f"Alpha should see 1 student and 2 Present, got {kpis(a)}"
    assert kpis(b) == [1, 1], f"Beta should see 1 student and 1 Present, got {kpis(b)}"
    assert "Secret Student One" not in b, "Beta can see Alpha's student name"
    assert "R-SECRET1" not in b, "Beta can see Alpha's roll number"
    assert "Other Student Two" in b

@test
def classes_page_lists_only_own_classes():
    h.fresh()
    b = h.login("/faculty_login", "tch_b@x.com").get("/teacher/classes").get_data(as_text=True)
    assert "ClassB-OTHER" in b and "ClassA-SECRET" not in b
    assert "SubA-SECRET" not in b

@test
def cannot_enroll_student_into_other_teachers_class():
    ids = h.fresh()
    client = h.login("/faculty_login", "tch_b@x.com")
    client.post("/teacher/enrollments", data={"class_id": ids["cA"], "student_ids": [ids["sS2"]]})
    n = h.count("SELECT COUNT(*) FROM student_enrollments WHERE class_id = ? AND student_id = ?",
                (ids["cA"], ids["sS2"]))
    assert n == 0, "Beta enrolled a student into Alpha's class"

@test
def enrollments_page_hides_other_teachers_class():
    h.fresh()
    client = h.login("/faculty_login", "tch_b@x.com")
    body = client.get("/teacher/enrollments?class_id=1").get_data(as_text=True)
    assert "ClassA-SECRET" not in body and "R-SECRET1" not in body

@test
def cannot_create_session_in_other_teachers_class():
    ids = h.fresh()
    client = h.login("/faculty_login", "tch_b@x.com")
    client.post("/teacher/sessions", data={"class_id": ids["cA"], "subject_id": ids["subB"], "duration": 10})
    n = h.count("SELECT COUNT(*) FROM attendance_sessions WHERE class_id = ?", (ids["cA"],))
    assert n == 3, f"Alpha's class got a new session from Beta ({n} sessions)"

@test
def cannot_use_other_teachers_subject():
    ids = h.fresh()
    client = h.login("/faculty_login", "tch_b@x.com")
    client.post("/teacher/sessions", data={"class_id": ids["cB"], "subject_id": ids["subA"], "duration": 10})
    n = h.count("SELECT COUNT(*) FROM attendance_sessions WHERE class_id = ? AND subject_id = ?",
                (ids["cB"], ids["subA"]))
    assert n == 0, "Beta used Alpha's subject"

@test
def cannot_open_other_teachers_session_qr_or_image():
    ids = h.fresh()
    client = h.login("/faculty_login", "tch_b@x.com")
    assert client.get(f"/teacher/sessions/{ids['aopen']}").status_code == 404
    assert client.get(f"/teacher/sessions/{ids['aopen']}/qr.png").status_code == 404

@test
def cannot_close_other_teachers_session():
    ids = h.fresh()
    client = h.login("/faculty_login", "tch_b@x.com")
    assert client.post(f"/teacher/sessions/{ids['aopen']}/close").status_code == 404
    status = h.count("SELECT status FROM attendance_sessions WHERE id = ?", (ids["aopen"],))
    assert h.db().execute("SELECT status FROM attendance_sessions WHERE id = ?", (ids["aopen"],)).fetchone()[0] == "open"

@test
def reports_hide_other_teachers_class():
    h.fresh()
    body = h.login("/faculty_login", "tch_b@x.com").get("/teacher/reports?class_id=1").get_data(as_text=True)
    assert "Secret Student One" not in body and "R-SECRET1" not in body and "ClassA-SECRET" not in body

@test
def csv_download_refuses_other_teachers_class():
    h.fresh()
    client = h.login("/faculty_login", "tch_b@x.com")
    r = client.get("/teacher/reports.csv?class_id=1")
    assert r.status_code == 404, r.status_code
    assert "Secret Student One" not in r.get_data(as_text=True)

@test
def cannot_delete_other_teachers_class():
    ids = h.fresh()
    h.login("/faculty_login", "tch_b@x.com").post(f"/teacher/classes/{ids['cA']}/delete")
    assert h.count("SELECT COUNT(*) FROM classes WHERE id = ?", (ids["cA"],)) == 1

@test
def owner_still_sees_and_controls_own_data():
    ids = h.fresh()
    a = h.login("/faculty_login", "tch_a@x.com")
    assert "Secret Student One" in a.get(f"/teacher/reports?class_id={ids['cA']}").get_data(as_text=True)
    assert a.get(f"/teacher/sessions/{ids['aopen']}").status_code == 200
    assert a.get("/teacher/reports.csv?class_id=%d" % ids["cA"]).status_code == 200

@test
def owner_can_close_own_session():
    ids = h.fresh()
    h.login("/faculty_login", "tch_a@x.com").post(f"/teacher/sessions/{ids['aopen']}/close")
    st = h.db().execute("SELECT status FROM attendance_sessions WHERE id = ?", (ids["aopen"],)).fetchone()[0]
    assert st == "closed"

for name, status, msg in results:
    print(f"{status:5s} {name}" + (f"  -> {msg}" if msg else ""))
fails = [r for r in results if r[1] != "PASS"]
print(f"\n{len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
