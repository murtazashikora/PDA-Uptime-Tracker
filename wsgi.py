from server import app, init_db, load_state_from_db, ensure_vapid_keys, start_background_workers

init_db()
load_state_from_db()
ensure_vapid_keys()
start_background_workers()
