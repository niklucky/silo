#!/usr/bin/env python3
"""Login form playground for testing the extension's form filler.

    python3 scripts/login-form-server.py              # http://localhost:8200, nikita / s3cret
    python3 scripts/login-form-server.py 9000 me:pw   # custom port and credentials

Pages: a classic form, a React-style controlled form, a two-step sign-in, a
sign-up form (must not be offered), and a login form inside an iframe. Every
sign-in posts to /login, which says whether the credentials were right.
"""
import html
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8200
user, _, password = (sys.argv[2] if len(sys.argv) > 2 else "nikita:s3cret").partition(":")

STYLE = """
<style>
  body { font: 15px system-ui, sans-serif; max-width: 420px; margin: 40px auto; }
  form, .form { display: flex; flex-direction: column; gap: 8px; }
  input, button { font: inherit; padding: 6px 8px; }
  nav a { margin-right: 10px; }
</style>
"""

NAV = """
<nav><a href="/">index</a><a href="/classic">classic</a><a href="/react">react</a>
<a href="/two-step">two-step</a><a href="/signup">signup</a><a href="/frame">iframe</a></nav>
"""


def page(title, body):
    return f"<!doctype html><meta charset=utf-8><title>{title}</title>{STYLE}{NAV}<h1>{title}</h1>{body}"


PAGES = {
    "/": page(
        "Login form playground",
        f"<p>Credentials: <code>{html.escape(user)}</code> / <code>{html.escape(password)}</code></p>"
        "<ul><li><b>classic</b>: plain form, should offer and fill</li>"
        "<li><b>react</b>: no &lt;form&gt;, values tracked from input events, should fill</li>"
        "<li><b>two-step</b>: email first, password on the next page</li>"
        "<li><b>signup</b>: password + repeat, should <i>not</i> offer anything</li>"
        "<li><b>iframe</b>: classic form inside a same-origin frame</li></ul>",
    ),
    "/classic": page(
        "Classic form",
        """<form method="post" action="/login">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button>Sign in</button>
</form>""",
    ),
    "/react": page(
        "Controlled inputs",
        """<div class="form">
  <input id="login" aria-label="Email or username">
  <input id="pw" type="password" aria-label="Password">
  <button id="go">Sign in</button>
  <p id="state">state: {}</p>
</div>
<script>
  // Like a React controlled form: the DOM value is ignored, only input events count.
  const state = { login: "", pw: "" };
  for (const id of ["login", "pw"]) {
    document.getElementById(id).addEventListener("input", (e) => {
      state[id] = e.target.value;
      document.getElementById("state").textContent = "state: " + JSON.stringify({ login: state.login, pw: state.pw ? "•".repeat(state.pw.length) : "" });
    });
  }
  document.getElementById("go").onclick = async () => {
    const body = new URLSearchParams({ username: state.login, password: state.pw });
    const res = await fetch("/login", { method: "POST", body });
    document.body.insertAdjacentHTML("beforeend", await res.text());
  };
</script>""",
    ),
    "/two-step": page(
        "Two-step sign-in, step 1",
        """<form method="get" action="/two-step/password">
  <input name="email" autocomplete="username" placeholder="Email or username">
  <button>Next</button>
</form>""",
    ),
    "/signup": page(
        "Sign up",
        """<form method="post" action="/login">
  <input name="username" placeholder="Choose a username">
  <input name="password" type="password" placeholder="Password">
  <input name="repeat" type="password" placeholder="Repeat password">
  <button>Create account</button>
</form>""",
    ),
    "/frame": page(
        "Login in an iframe",
        '<iframe src="/classic" style="width:100%;height:260px;border:1px solid #888"></iframe>',
    ),
}


class Handler(BaseHTTPRequestHandler):
    def send_html(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/two-step/password":
            email = html.escape(parse_qs(query).get("email", [""])[0], quote=True)
            self.send_html(
                200,
                page(
                    "Two-step sign-in, step 2",
                    f"""<form method="post" action="/login">
  <input name="username" autocomplete="username" value="{email}" hidden>
  <p>Signing in as <b>{email or "?"}</b></p>
  <input name="password" type="password" autocomplete="current-password" placeholder="Password">
  <button>Sign in</button>
</form>""",
                ),
            )
        elif path in PAGES:
            self.send_html(200, PAGES[path])
        else:
            self.send_html(404, page("Not found", ""))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode())
        got_user = form.get("username", [""])[0]
        got_password = form.get("password", [""])[0]
        ok = got_user == user and got_password == password
        self.result = "ok" if ok else f"wrong ({json.dumps(got_user)})"
        message = f"Signed in as {html.escape(got_user)}" if ok else "Wrong username or password"
        self.send_html(200 if ok else 403, f'<p id="result">{message}</p>')

    def log_message(self, fmt, *args):
        extra = f" login={self.result}" if getattr(self, "result", None) else ""
        sys.stderr.write(f"{self.command} {self.path}{extra}\n")


print(f"Login form test server on http://localhost:{port}  user={user} password={password}")
ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
