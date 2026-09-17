# The flag contract — what your service must implement

The referee is the only thing that plants and retrieves flags. For a protocol
to score, your stack must answer these requests *on that protocol*
(RULES §6: "up" means correct for that specific version **and** a completed
flag round-trip).

Everything is line-oriented on purpose. You are writing the HTTP parser by
hand; you should not also have to write a JSON parser to play.

---

## 1. Endpoints

| Request | Body | Success response body |
|---|---|---|
| `GET /health` | — | anything non-empty |
| `POST /register` | `<user>\n<pass>\n` | a single-line opaque token, ≤ 512 bytes |
| `PUT /note` | the note contents (a flag) | a single-line note id, ≤ 256 bytes, no `/` |
| `GET /note/{id}` | — | the exact bytes stored by `PUT /note` |

`PUT /note` and `GET /note/{id}` carry `Authorization: Bearer <token>`.

**The security property the game rests on:** `GET /note/{id}` must return the
note **only** to the token that created it. Everything else — traversal, IDOR,
auth bypass, parser confusion, a hijacked TCP stream — is the opponent's
route to a flag you own. That is the point; leave bugs at your peril.

Status codes: `200` on success, any `4xx` on refusal. The referee treats
`2xx` as success and everything else as failure.

## 2. Per-version notes

* **HTTP/0.9** — request is a bare `GET /health\r\n`, response is the naked
  body with **no status line**, terminated by closing the connection. Liveness
  only: 0.9 carries no note app, so it plants no flag (RULES §3).
* **HTTP/1.0** — the referee sends `Connection: close` and expects your status
  line to read `HTTP/1.0`. Frame the body with `Content-Length` or by closing.
  `Transfer-Encoding` is rejected: it is not a 1.0 feature.
* **HTTP/1.1** — status line must read `HTTP/1.1`, `Content-Length` or
  `chunked` framing is required, and **the connection must persist**: the
  prober sends a second request on the same socket. Hanging up after one
  response fails the rung.
* **HTTP/2 (h2c)** — prior knowledge only. Preface, `SETTINGS` exchange,
  HPACK'd `HEADERS`, `DATA`, `END_STREAM`. No `Upgrade:` dance — that is a 1.1
  mechanism. `CONTINUATION` frames are not supported by the prober, so keep
  your response header block inside one frame (it is a handful of bytes).
  Prefer an indexed or plain-literal `:status`; see §6.
* **HTTP/3** — see §5.

## 3. The UDP rung

`ECHO <nonce>` → the identical datagram back. That is the whole conformance
test, and it is worth 2 points a tick (RULES §7).

With `game.udp_flag_fixture = true` the rung also carries a transport-level
flag surface:

```
SET <key> <flag>   ->  OK
GET <key>          ->  <flag>
```

A flag stolen off this rung scores the transport tier (75) rather than the
app tier (50).

## 4. What the referee does each tick

```
register a throwaway user        POST /register
plant a fresh flag as that user  PUT  /note
retrieve the flag from K-1 ticks GET  /note/{id}      <- the SLA check
expire everything older than K
```

A flag lives K ticks (default 5). Both steps must work: a service that plants
but cannot retrieve is *down*, and so is one that serves `/health` while
refusing to implement the note app.

## 5. HTTP/3

The referee ships **no QUIC client**. Writing QUIC and TLS 1.3 from scratch is
the players' apex rung (RULES §4); a half-correct referee implementation would
score it wrongly, so there isn't one. Until you configure
`probe.h3_probe_cmd`, HTTP/3 shows as down on the grid and scores nothing.

The hook is a command that reads one JSON object on stdin and writes one on
stdout:

```jsonc
// in:  {"op":"health","host":"10.0.1.2","port":8080,"version":"3","path":"/health"}
// out: {"ok":true}

// in:  {"op":"plant","host":...,"port":...,"flag":"FLAG_..."}
// out: {"ok":true,"id":"...","token":"...","user":"..."}   // echoed back as `ref`

// in:  {"op":"fetch","host":...,"port":...,"ref":{"id":...,"token":...}}
// out: {"ok":true,"body":"FLAG_..."}

// failure, any op: {"ok":false,"error":"why"}
```

Any error, non-zero exit, or timeout marks the rung down for that tick. Agree
on one prober between all players before anyone declares `"3"` — whatever you
use, it must be the *same* for everyone, or HTTP/3 is not scored fairly.

## 6. Known prober limitation

The h2c prober decodes HPACK indexed fields and literals but **not Huffman-
coded values**. A Huffman-coded `:status` is read as "unknown", and the
response is then judged on framing and body alone — a correct response still
passes. Nothing else is affected, because request headers are encoded by the
referee (never Huffman) and response bodies are `DATA` frames. If you want
your status codes to be read precisely, send `:status` as a static-table index
(`0x88` for 200) or a plain literal.
