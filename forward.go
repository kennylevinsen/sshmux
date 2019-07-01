package sshmux

import (
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func proxy(reqs1, reqs2 <-chan *ssh.Request, channel1, channel2 ssh.Channel) {
	var closer sync.Once
	closeFunc := func() {
		channel1.Close()
		channel2.Close()
	}

	defer closer.Do(closeFunc)

	closerChan := make(chan bool, 1)

	go func() {
		io.Copy(channel1, channel2)
		closerChan <- true
	}()

	go func() {
		io.Copy(channel2, channel1)
		closerChan <- true
	}()

	for {
		select {
		case req := <-reqs1:
			if req == nil {
				return
			}
			b, err := channel2.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)

		case req := <-reqs2:
			if req == nil {
				return
			}
			b, err := channel1.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)
		case <-closerChan:
			return
		}
	}
}

// https://tools.ietf.org/html/rfc4254
type channelOpenDirectMsg struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

// ChannelForward establishes a secure channel forward (ssh -W) to the server
// requested by the user, assuming it is a permitted host.
func (s *Server) ChannelForward(session *Session, newChannel ssh.NewChannel) {
	var msg channelOpenDirectMsg
	ssh.Unmarshal(newChannel.ExtraData(), &msg)
	address := fmt.Sprintf("%s:%d", msg.RAddr, msg.RPort)

	var selected *Remote
	for _, remote := range session.Remotes {
		for _, name := range remote.Names {
			if name == address {
				selected = remote
				break
			}
		}
	}

	if selected == nil {
		newChannel.Reject(ssh.Prohibited, "remote host access denied for user")
		return
	}

	// Log the selection
	if s.Selected != nil {
		if err := s.Selected(session, selected.Address); err != nil {
			newChannel.Reject(ssh.Prohibited, "access denied")
			return
		}
	}

	conn, err := s.Dialer("tcp", selected.Address)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("error: %v", err))
		return
	}

	channel, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}

	go ssh.DiscardRequests(reqs)
	var closer sync.Once
	closeFunc := func() {
		channel.Close()
		conn.Close()
	}

	go func() {
		io.Copy(channel, conn)
		closer.Do(closeFunc)
	}()

	io.Copy(conn, channel)
	closer.Do(closeFunc)
}

type rw struct {
	io.Reader
	io.Writer
}

// SessionForward performs a regular forward, providing the user with an
// interactive remote host selection if necessary. This forwarding type
// requires agent forwarding in order to work.
func (s *Server) SessionForward(session *Session, newChannel ssh.NewChannel, chans <-chan ssh.NewChannel) {

	// Okay, we're handling this as a regular session
	sesschan, sessReqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer sesschan.Close()

	agentCh := make(chan struct{})

	// Proxy the channel and its requests
	maskedReqs := make(chan *ssh.Request, 1)
	go func() {
		for req := range sessReqs {
			// Filter out auth agent requests, and answer some request types immediately in order to cope with PuTTY.
			switch req.Type {
			case "auth-agent-req@openssh.com":
				if req.WantReply {
					req.Reply(true, []byte{})
				}
				agentCh <- struct{}{}
				continue
			case "pty-req", "shell":
				if req.WantReply {
					req.Reply(true, []byte{})
					req.WantReply = false
				}
			case "keepalive@openssh.com":
				if req.WantReply {
					req.Reply(true, []byte{})
					req.WantReply = false
				}
			}
			maskedReqs <- req
		}
	}()

	stderr := sesschan.Stderr()

	var remote *Remote
	switch len(session.Remotes) {
	case 0:
		fmt.Fprintf(stderr, "User has no permitted remote hosts.\r\n")
		return
	case 1:
		remote = session.Remotes[0]
		fmt.Fprintf(stderr, "Selecting only remote: %s\r\n", remote.Description)
	default:
		comm := rw{Reader: sesschan, Writer: stderr}
		if s.Interactive == nil {
			remote, err = DefaultInteractive(comm, session)
		} else {
			remote, err = s.Interactive(comm, session)
		}
		if err != nil {
			return
		}
	}

	// Log the selection
	if s.Selected != nil {
		if err = s.Selected(session, remote.Address); err != nil {
			fmt.Fprintf(stderr, "Remote host selection denied.\r\n")
			return
		}
	}

	fmt.Fprintf(stderr, "Connecting to %s\r\n", remote.Address)

	// Set up the agent
	select {
	case <-agentCh:
	case <-time.After(1 * time.Second):
		fmt.Fprintf(stderr, "\r\n====== sshmux ======\r\n")
		fmt.Fprintf(stderr, "sshmux requires either agent forwarding or secure channel forwarding.\r\n")
		fmt.Fprintf(stderr, "Either enable agent forwarding (-A), or use a ssh -W proxy command.\r\n")
		fmt.Fprintf(stderr, "For more info, see the sshmux wiki.\r\n")
		return
	}

	agentChan, agentReqs, err := session.Conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		fmt.Fprintf(stderr, "agent forwarding failed: %+v", err)
		return
	}
	defer agentChan.Close()
	go ssh.DiscardRequests(agentReqs)

	// Set up the client

	ag := agent.NewClient(agentChan)

	clientConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User: session.Conn.User(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(ag.Signers),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				comm := rw{Reader: sesschan, Writer: stderr}
				return KeyboardChallenge(comm, user, instruction, questions, echos)
			}),
			ssh.PasswordCallback(func() (string, error) {
				comm := rw{Reader: sesschan, Writer: stderr}
				return PasswordCallback(comm, session.Conn.User() + "@" + remote.Address + ":")
			}),
		},
	}

	conn, err := s.Dialer("tcp", remote.Address)
	if err != nil {
		fmt.Fprintf(stderr, "Connect failed: %v\r\n", err)
		return
	}
	defer conn.Close()

	clientConn, clientChans, clientReqs, err := ssh.NewClientConn(conn, remote.Address, clientConfig)
	if err != nil {
		fmt.Fprintf(stderr, "Client connection setup failed: %v\r\n", err)
		return
	}
	client := ssh.NewClient(clientConn, clientChans, clientReqs)

	// Handle all incoming channel requests
	go func() {
		for newChannel = range chans {
			if newChannel == nil {
				return
			}

			channel2, reqs2, err := client.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
			if err != nil {
				x, ok := err.(*ssh.OpenChannelError)
				if ok {
					newChannel.Reject(x.Reason, x.Message)
				} else {
					newChannel.Reject(ssh.Prohibited, "remote server denied channel request")
				}
				continue
			}

			channel, reqs, err := newChannel.Accept()
			if err != nil {
				channel2.Close()
				continue
			}
			go proxy(reqs, reqs2, channel, channel2)
		}
	}()

	// Forward the session channel
	channel2, reqs2, err := client.OpenChannel("session", []byte{})
	if err != nil {
		fmt.Fprintf(stderr, "Remote session setup failed: %v\r\n", err)
		return
	}

	proxy(maskedReqs, reqs2, sesschan, channel2)
}
