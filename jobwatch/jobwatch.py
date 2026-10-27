#!/usr/bin/env python3
"""jobwatch: is every scheduled job running? -> an Uptime Kuma push monitor "Scheduled jobs".

- cron jobs run through jobrun, which writes ~/.jobs/<name>.ok ("<time> <maxage>") after each success.
  A job is LATE when its last success is older than its maxage (a single failed run is not enough).
- system timers: the last run of the service must have Result=success (systemctl, no root needed); a failure only
  counts once it has lasted 20 minutes (a frequent timer usually fixes itself on the next run).
Pushes up (all fine) or down (with the names) every 5 minutes; if this script stops, Kuma goes down by itself
after 15 minutes (set the push monitor's heartbeat interval to match). Kuma alerts + diag-agent take it from there.
Push token: ~/.config/kuma-jobs-token. Optional: a second push monitor for a Cloudflare tunnel, fed from cloudflared's
own /ready endpoint (an http check of a site behind Cloudflare Access only ever sees the login page, so it stays
green with the tunnel down). Token ~/.config/kuma-tunnel-token; skipped when that file does not exist."""
import glob
import json
import os
import subprocess
import time
import urllib.parse
import urllib.request

JOBS = os.path.expanduser("~/.jobs")
KUMA = os.environ.get("KUMA_URL", "http://127.0.0.1:3001").rstrip("/")
# systemd timers to watch (service name without .service); edit for your machine
TIMERS = os.environ.get("JOBWATCH_TIMERS", "diag-watch logrotate apt-daily-upgrade").split()


def late_jobs(now):
    out = []
    for p in glob.glob(f"{JOBS}/*.ok"):
        try:
            with open(p) as f:
                at, maxage = (int(x) for x in f.read().split()[:2])
        except (OSError, ValueError):
            continue
        if now - at > maxage:
            out.append(f"{os.path.basename(p)[:-3]} (last OK {int((now - at) / 3600)} h ago)")
    return out


GRACE = 20 * 60
SEEN = os.path.join(JOBS, "timers-failing.json")   # unit -> first time seen failing


def failed_timers():
    try:
        seen = json.load(open(SEEN))
    except (OSError, ValueError):
        seen = {}
    now, out, still = time.time(), [], {}
    for u in TIMERS:
        r = subprocess.run(["systemctl", "show", f"{u}.service", "-p", "Result", "--value"], capture_output=True, text=True, timeout=10)
        res = r.stdout.strip()
        if res and res != "success":
            still[u] = seen.get(u, now)
            if now - still[u] >= GRACE:
                out.append(f"{u} ({res})")
    with open(SEEN, "w") as f:
        json.dump(still, f)
    return out


def push(token_file, ok, msg):
    tok = open(os.path.expanduser(token_file)).read().strip()
    q = urllib.parse.urlencode({"status": "up" if ok else "down", "msg": msg[:250], "ping": ""})
    for i in range(3):       # Kuma is sometimes slow for a few seconds; one lost push turned the tunnel red (10-26)
        try:
            urllib.request.urlopen(f"{KUMA}/api/push/{tok}?{q}", timeout=20).read()
            return True
        except Exception as e:
            err = e
            time.sleep(10)
    print("push failed:", token_file, type(err).__name__)
    return False


def tunnel():
    try:
        d = json.loads(urllib.request.urlopen("http://127.0.0.1:20241/ready", timeout=5).read())
        n = int(d.get("readyConnections") or 0)
        return n > 0, f"{n} edge connections"
    except Exception as e:
        return False, f"cloudflared not ready: {type(e).__name__}"


def main():
    bad = late_jobs(time.time()) + failed_timers()
    push("~/.config/kuma-jobs-token", not bad, ("Late or failed: " + ", ".join(bad)) if bad else "all jobs on time")
    msg = "not watched"
    if os.path.exists(os.path.expanduser("~/.config/kuma-tunnel-token")):
        ok, msg = tunnel()
        push("~/.config/kuma-tunnel-token", ok, msg)
    print(("DOWN: " + ", ".join(bad)) if bad else "ok", "| tunnel:", msg)


if __name__ == "__main__":
    main()
