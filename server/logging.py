import os
import server.config as config

INFO_LOG_FILE = "info.log"


def log_info(*args, sep: str = " "):
	logs_path = config.config.server.logs
	if not logs_path.exists():
		os.makedirs(logs_path)

	info_path = logs_path.joinpath(INFO_LOG_FILE)
	with open(info_path, "a") as f:
		f.write(sep.join(str(a) for a in args) + "\n")
