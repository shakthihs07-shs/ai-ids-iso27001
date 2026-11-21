# OpenCanary logs only requests for its fake login page and answers every other path with a 404 it never logs.
# Scanners probe exactly those paths (/.env, /cgi-bin/..., exploit payloads), so log them as HTTP GETs too,
# with the query string, then start OpenCanary's own tac file unchanged.
import os
import shutil

from opencanary.modules import http

_render = http.Error.render


def render(self, request):
    self.factory.log({"SKIN": self.skin, "HOSTNAME": request.getRequestHostname(), "PATH": request.uri,
                      "USERAGENT": request.getHeader("user-agent") or "<not supplied>"},
                     transport=request.transport, logtype=self.factory.logger.LOG_HTTP_GET)
    return _render(self, request)


http.Error.render = render
_tac = os.path.join(os.path.dirname(shutil.which("opencanaryd")), "opencanary.tac")
with open(_tac) as _f:
    exec(compile(_f.read(), _tac, "exec"))
