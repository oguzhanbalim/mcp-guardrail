# mcp-guardrail

A firewall for MCP tool calls: the agent only sees the tools your YAML names, and every call
leaves a line in a log before it runs.

MCP servers usually expose everything they have, and the choice of what to run sits with a
model reading tool descriptions. This proxy sits between client and server and enforces a
short policy you can read in a code review.

## Quickstart

```bash
pip install -e ".[dev]"
python examples/demo.py audit.jsonl
```

The demo runs a real SDK client, the real proxy and a small in-memory demo server in one
process. Its "human" is a function that approves everything except order `ORD-999`. Using
[`examples/policy.yaml`](examples/policy.yaml):

```yaml
version: 1
approval_timeout_seconds: 60

tools:
  read_file:
    read_only: true
    args:
      path: { path_prefix: /workspace }

  write_file:
    approval: true
    args:
      path: { path_prefix: /workspace }
      content: { max_length: 10000, redact: true }

  issue_refund:
    approval: true
    args:
      order_id: { pattern: "ORD-[0-9]+" }
      amount: { min: 0.01, max: 100 }
```

Output:

```
visible tools: read_file, write_file, issue_refund
ok    read_file {'path': '/workspace/notes.txt'}
      -> synthetic demo note

ERROR read_file {'path': '/workspace/../etc/secrets'}
      -> mcp-guardrail: denied: argument 'path' resolves outside ['/workspace']
ok    write_file {'path': '/workspace/out.txt', 'content': 'hello'}
      -> wrote 5 bytes to /workspace/out.txt
ok    issue_refund {'order_id': 'ORD-1', 'amount': 40}
      -> refunded 40.0 on ORD-1 (1 refund(s) so far)
ERROR issue_refund {'order_id': 'ORD-1', 'amount': 5000}
      -> mcp-guardrail: denied: argument 'amount' 5000 is above the maximum of 100
ERROR issue_refund {'order_id': 'ORD-999', 'amount': 10}
      -> mcp-guardrail: not approved (rejected)
ERROR delete_everything {}
      -> mcp-guardrail: denied: tool 'delete_everything' is not in the policy
```

The server also has `delete_everything`. It is not in the policy, so the client never sees it,
and calling it by name anyway is denied.

The log for the refund that the human rejected, as written:

```json
{"args": {"amount": 10, "order_id": "ORD-999"}, "call_id": "df29b9c8a12a40209d13cab72ef552de", "event": "decision", "reason": "policy requires approval for 'issue_refund'", "tool": "issue_refund", "ts": "2026-10-30T09:14:51.184+00:00", "verdict": "needs_approval"}
{"call_id": "df29b9c8a12a40209d13cab72ef552de", "event": "approval", "outcome": "rejected", "tool": "issue_refund", "ts": "2026-10-30T09:14:51.184+00:00"}
```

## Use it with a real server

Put it in front of any stdio MCP server by replacing the server command in your client config:

```bash
mcp-guardrail run --policy policy.yaml --audit audit.jsonl --approver tty -- python my_server.py
```

Compare a policy with what a server really offers. A read-only claim that the server's own
annotations contradict is a `CONFLICT`, and a policy entry the server lacks is `MISSING`:

```
$ mcp-guardrail check --policy examples/policy.yaml -- python -m mcp_guardrail.demo_server
delete_everything        hidden
issue_refund             write, approval, 2 arg rule(s)
read_file                read-only, 1 arg rule(s)
write_file               write, approval, 2 arg rule(s)
```

Test one call without any server. Exit status is 0 for allow, 1 for deny, 2 for needs approval:

```
$ mcp-guardrail explain --policy examples/policy.yaml read_file '{"path": "/workspace/../etc/secrets"}'
deny: argument 'path' resolves outside ['/workspace']
```

## What it enforces

| Control | Behavior |
| --- | --- |
| Allowlist | A tool not in the policy is hidden from `tools/list` and denied on call. |
| Read-only | `read_only_mode: true` hides and denies everything not marked `read_only`. A tool whose server contradicts a `read_only` claim is blocked. |
| Paths | `path_prefix` normalizes first, so `/workspace/../etc` and `/workspace-evil` fail. Percent-decoded forms are checked too. Backslashes and control characters are refused. |
| Numbers | `min` and `max` refuse strings, booleans, NaN and infinity. |
| Other values | `one_of`, `pattern` (full match), `max_length`. |
| Shape | A declared argument must be present unless `optional`, since a server-side default was never checked. An undeclared argument is denied unless `allow_other_args`. |
| Approval | `approval: true` asks after the argument rules pass. Rejection, a crash, a timeout or a non-`True` answer all mean no. |
| Audit | Every decision is appended and fsynced before anything runs. If that write fails, the call is refused. `redact: true` keeps an argument's value out of the log. |

A typo in a policy (`aproval: true`) is a load error rather than a control that silently
disappears.

Denials come back as MCP tool errors, not protocol errors, so the model can read the reason
and change course.

## Approvers

The proxy's stdin and stdout carry the protocol, so it cannot prompt on them.

- `--approver deny` (default): nothing that needs approval can run.
- `--approver tty`: prompts on `/dev/tty`. Type `yes`. Agent-chosen arguments are JSON-escaped
  so ANSI sequences cannot repaint the prompt.
- `--approver "cmd:./approve.sh"`: runs a command with the request as JSON on stdin. Exit 0
  approves. Use it to hook up a queue or a chat prompt.

MCP elicitation is not used. When I tried it through the SDK's in-process client on the
current protocol version, the server side raised `NoBackChannelError`, so it is not a route I
can test here.

## Tests

```
$ pytest
79 passed in 3.75s
```

These are self-written tests. They use the real `mcp` SDK (2.3.0) over its in-process transport
and over real stdio subprocess pipes, against the bundled demo server. The tty approver is
tested on a real pty. No model is involved and nothing touches the network.

## Limits

- The proxy reasons about strings, not the filesystem. A symlink inside an allowed prefix that
  points outside it passes. Run the server with its own OS-level confinement as well.
- Argument rules apply to top-level arguments only. A nested object can be permitted or
  refused as a whole; its contents are not inspected.
- The rules cannot see what a tool does. `read_only: true` is your claim, and annotations are
  hints from the server. A lying server that declares nothing is not caught.
- Tool descriptions are forwarded unchanged and not scanned for prompt injection. Tool results
  are also forwarded unchanged. Results are not logged, only their status and duration.
- Only tools are proxied. Resources, prompts, sampling, progress and notifications are dropped.
- Conflicts are refreshed on `tools/list`, so a server that changes a tool's annotations later
  is not noticed until the next listing.
- The transport is stdio on both sides. Streamable HTTP is not implemented.
- The log is append-only by how this code writes it. It is not tamper-evident.
- Redaction covers declared arguments only. Arguments to unknown tools and undeclared
  arguments are logged as sent, because they are the evidence of what was attempted.
- `mcp` is pinned to `>=2.3,<3`. Tested locally on Python 3.12 only; CI is configured for 3.11
  and 3.12 but has not run, since this repository has not been pushed.

## License

MIT
