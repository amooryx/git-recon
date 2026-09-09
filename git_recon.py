import urllib.request, urllib.error, rclib
def run(ctx):
    base = (ctx.target if "://" in ctx.target else "https://" + ctx.target).rstrip("/")
    for path in ["/.git/HEAD", "/.git/config", "/.svn/entries", "/.env"]:
        url = base + path
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent":"redcell"}), timeout=12)
            body = r.read(200).decode("latin1")
            if path == "/.git/HEAD" and "ref:" in body:
                ctx.finding("Exposed Git repository (.git/HEAD readable)", "high", detail=url)
            elif path == "/.git/config" and "[core]" in body:
                ctx.finding("Exposed Git config", "high", detail=url)
            elif path == "/.env" and "=" in body:
                ctx.finding("Exposed environment file", "high", detail=url)
            elif path == "/.svn/entries":
                ctx.finding("Exposed SVN metadata", "medium", detail=url)
            else:
                ctx.step(f"{path} -> {r.status}")
        except urllib.error.HTTPError as e:
            ctx.step(f"{path} -> {e.code}")
        except Exception:
            ctx.step(f"{path} -> unreachable")
    return 0
rclib.main("git-recon", "Detect exposed VCS / env metadata", run)
