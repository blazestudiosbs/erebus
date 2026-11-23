# Command-Center API — what Erebus needs

**Audience:** whoever builds or operates `command-center` (the local model server).
**Why:** the Erebus copilot ("Ask Erebus") sends the current engagement state to a
language model and shows its suggestions. It can run against a local server instead
of a cloud API. This is the exact contract that server must satisfy.

---

## TL;DR

Erebus speaks the **OpenAI-compatible chat API**. The simplest way to satisfy this
is to **run Ollama** (optionally with Open WebUI in front of it) — it already
provides every endpoint below, natively. Only build a custom server/proxy if you
can't run Ollama; if so, implement the two endpoints **exactly** as specified.

Erebus is pointed at the server from the copilot's ⚙ settings with three fields:

| Field    | Example                        | Notes                                  |
|----------|--------------------------------|----------------------------------------|
| Base URL | `http://command-center:3000`   | root that the paths below hang off     |
| Model    | `llama3`                       | a model the server actually has loaded |
| API key  | *(optional)*                   | sent as a bearer token if auth is on   |

Erebus **appends** paths to the Base URL. So the Base URL must be the root under
which `/v1/chat/completions` and `/v1/models` live. If your OpenAI API is mounted
under a prefix, include it in the Base URL (e.g. `http://command-center:3000/ollama`
→ Erebus calls `http://command-center:3000/ollama/v1/chat/completions`).

---

## Endpoint 1 — chat completions  (REQUIRED)

This is what the bot calls for every question.

**Request**

```
POST {base_url}/v1/chat/completions
Content-Type: application/json
Accept: application/json
Authorization: Bearer <api key>        # only if the server requires auth
```
```json
{
  "model": "llama3",
  "max_tokens": 512,
  "stream": false,
  "messages": [
    { "role": "system", "content": "…engagement guardrails…" },
    { "role": "user",   "content": "…the question + engagement state…" }
  ]
}
```

- `stream` is always `false` — return the whole answer in one JSON body
  (Erebus does not read a streamed/SSE response here).
- `messages` is standard OpenAI chat format: a system message, then a user message.

**Response (HTTP 200)**

```json
{
  "choices": [
    { "message": { "role": "assistant", "content": "…the answer…" } }
  ]
}
```

Erebus reads exactly `choices[0].message.content`. Everything else in the body is
ignored. Empty/missing content is treated as an error.

---

## Endpoint 2 — list models  (for the "Test connection" button)

Lets the operator confirm the URL and pick a model. Implement **either** form —
Erebus tries `/v1/models` first, then falls back to `/api/tags`.

**OpenAI form (preferred)**
```
GET {base_url}/v1/models
```
```json
{ "data": [ { "id": "llama3" }, { "id": "mistral" } ] }
```

**Ollama-native form (fallback)**
```
GET {base_url}/api/tags
```
```json
{ "models": [ { "name": "llama3" }, { "name": "mistral" } ] }
```

---

## Authentication

- **No auth:** send nothing — Erebus works without a key.
- **Auth required:** Erebus sends `Authorization: Bearer <key>` on **every** request
  (chat *and* models). The operator stores the key once, in the Erebus vault, from
  the dashboard.
- Return **401** or **403** when the key is missing/invalid — Erebus surfaces that
  as "server requires an API key" instead of a cryptic failure.

> This is the cause of the current `HTTP 401`: `command-center:3000` requires a key
> and Erebus wasn't sending one. Either turn auth off for the Erebus host, or issue
> a key and have the operator save it in Erebus.

---

## Operational requirements

- **Reachable** from the machine running `erebus console --serve`, over the LAN, at
  `http://command-center:<port>`. Make sure the hostname resolves there (or use an IP).
- **Plain HTTP is fine.** Erebus explicitly allows `http://` for this local provider;
  TLS is not required for the local model host.
- **Response time:** Erebus currently waits up to **20 seconds** per request. A large
  model on CPU can exceed that. If yours needs longer, say so — the Erebus-side
  timeout can be raised.
- **CORS not required.** Erebus calls server-to-server (from the console host), not
  from the browser.

---

## Verify it yourself (before wiring Erebus)

Run these from the Erebus host, or anywhere on the LAN. Drop the `Authorization`
header if the server has no auth.

```bash
BASE=http://command-center:3000
KEY=replace-me

# 1) models list
curl -s "$BASE/v1/models" -H "Authorization: Bearer $KEY"
#    expect: {"data":[{"id":"llama3"}, ...]}

# 2) chat completion
curl -s "$BASE/v1/chat/completions" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $KEY" \
  -d '{"model":"llama3","stream":false,
       "messages":[{"role":"user","content":"say hi"}]}'
#    expect: {"choices":[{"message":{"content":"Hi! ..."}}]}
```

If both return the shapes shown, Erebus will connect.

---

## Then, in Erebus

Copilot **⚙** → provider **Ollama (local)** → set **URL** and **API key** (if any) →
**Save** → **Test connection** → pick a model from the chips → **Ask**.

---

## Checklist for the command-center team

- [ ] `POST /v1/chat/completions` returns `choices[0].message.content` (non-streaming)
- [ ] `GET /v1/models` (or `/api/tags`) lists model names
- [ ] Auth: bearer accepted; returns 401 when missing (if auth is enabled)
- [ ] Reachable from the Erebus host at `http://command-center:<port>`
- [ ] Responds within ~20 s (or tell us to wait longer)
