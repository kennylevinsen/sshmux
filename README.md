# sshmux [![GoDoc](https://godoc.org/github.com/joushou/sshmux?status.svg)](http://godoc.org/github.com/joushou/sshmux) [![Build Status](https://travis-ci.org/joushou/sshmux.svg?branch=master)](https://travis-ci.org/joushou/sshmux) [![Go Report Card](https://goreportcard.com/badge/joushou/sshmuxd)](https://goreportcard.com/report/joushou/sshmux)
SSH multiplexing library, allowing you to write "jump host" style proxies.

sshmux supports jumps through agent-forwarding or secure channel forwarding (ssh -W). For ssh session channels, it also allows for interactive selection of destination. Secure channel forwarding is not interactive, but simply verifies the requested final destination against the permitted hosts list.

sshmux only allows publickey authentication at the current time, but might allow for keyboardinteractive in the future.

# Limitations
sshmux can only forward normal sessions (ssh'ing directly to sshmux without a ProxyCommand) if agent forwarding is enabled. This is because your normal session authenticates to sshmux, but sshmux then has to authenticate you with the remote host, requiring a additional access to your agent. sshmux will, however, not forward your agent to the final remote host. Doing this is simple if wanted, but I have to decide on how this is toggled. This also means that the sftp and scp clients bundled with openssh cannot use normal session forwarding. If you want this to work, try to revive this *very* old bug report about it: https://bugzilla.mindrot.org/show_bug.cgi?id=831.

Using a "ssh -W" ProxyCommand circumvents this limitation, both for ssh and sftp/scp, and also bypasses the interactive server selection, as the client will inform sshmux of the wanted target directly. If the target is permitted, the user will be connected. This also provides more protection for the paranoid, as the connection to the final host is encrypted end-to-end, rather than being plaintext in the memory of sshmux (not something I would worry too much about if the server is solely in your control).

# But i just want to run it...
Look at sshmuxd instead, then: https://github.com/joushou/sshmuxd
