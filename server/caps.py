from __future__ import annotations

import ctypes
import ctypes.util
import grp
import logging
import os
import pwd

logger = logging.getLogger("portkey.caps")

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

PR_SET_KEEPCAPS = 8
PR_CAPBSET_DROP = 24

CAP_NET_ADMIN = 12
CAP_NET_RAW = 13

KEEP_CAPS = {CAP_NET_ADMIN, CAP_NET_RAW}
CAP_SCAN_MAX = 64


def errcheck(result: int, func: str) -> None:
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{func} failed")


def drop_privileges(
    user_name: str = "nobody",
    group_name: str = "nogroup",
) -> None:
    if os.geteuid() != 0:
        logger.debug("Already non-root (uid=%d), skipping privilege drop", os.geteuid())
        return

    try:
        pw = pwd.getpwnam(user_name)
    except KeyError:
        logger.warning("User '%s' not found, staying as root", user_name)
        return

    try:
        gr = grp.getgrnam(group_name)
    except KeyError:
        logger.warning(
            "Group '%s' not found, falling back to gid=%d", group_name, pw.pw_gid
        )
        target_gid = pw.pw_gid
    else:
        target_gid = gr.gr_gid

    errcheck(
        libc.prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0),
        "prctl(PR_SET_KEEPCAPS)",
    )
    logger.debug("PR_SET_KEEPCAPS enabled")

    for cap in range(CAP_SCAN_MAX):
        if cap not in KEEP_CAPS:
            libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)

    os.setgroups([])
    os.setgid(target_gid)
    os.setuid(pw.pw_uid)

    if os.getuid() == 0:
        logger.warning("Still running as root after setuid. capabilities may not work")
    else:
        logger.info(
        	"Dropped privileges to %s (uid=%d, gid=%d)",
            user_name,
            pw.pw_uid,
            target_gid,
        )
