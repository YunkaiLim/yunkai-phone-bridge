# Provenance

This public repository was prepared on 2026-09-30 as a sanitized source export from the owner's private Yunkai PhoneBridge working tree.

The export includes selected bridge source code, unit tests, example configuration, the optional local Control Center source, and the shared contract package needed by the bridge. It deliberately excludes machine/account bindings, the real tunnel ID, private runtime configuration, caches, private verification evidence, and binary tunnel clients.

The public candidate was re-scanned after export for owner-specific paths, real tunnel IDs, common credential/token formats, cache/runtime artifacts, binaries, and accidental pagination/truncation markers.

The earlier private-tree NOTICE containing `Copyright 2026 OpenAI` was traced to the upstream `openai/tunnel-client` distribution. That upstream NOTICE belongs to tunnel-client and is not a copyright claim over PhoneBridge. PhoneBridge does not bundle the tunnel-client/cloudflared executable in this public source repository.

Python packages and Android Platform Tools are installed separately and remain under their own licenses.
