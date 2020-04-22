package sshmux

import (
	"errors"
	"fmt"
	"io"
	"strconv"
)

// DefaultInteractive is the default server selection prompt for users during
// session forward.
func DefaultInteractive(comm io.ReadWriter, session *Session) (*Remote, error) {
	remotes := session.Remotes
	if len(remotes) == 0 {
		return nil, fmt.Errorf("no permitted remote hosts")
	}

	fmt.Fprintf(comm, "Welcome to sshmux, %s\r\n", session.Conn.User())
	for i, v := range remotes {
		fmt.Fprintf(comm, "    [%d] %s\r\n", i, v.Description)
	}

	// Beware, nasty input parsing loop
loop:
	for {
		fmt.Fprintf(comm, "Please select remote server: ")
		var buf []byte
		b := make([]byte, 1)
		var (
			n   int
			err error
		)
		for {
			if err != nil {
				return nil, err
			}
			n, err = comm.Read(b)
			if n == 1 {
				fmt.Fprintf(comm, "%s", b[0:1])
				switch b[0] {
				case '\r':
					fmt.Fprintf(comm, "\r\n")
					res, err := strconv.ParseInt(string(buf), 10, 64)
					if err != nil {
						fmt.Fprintf(comm, "input not a valid integer. Please try again\r\n")
						continue loop
					}
					if int(res) >= len(remotes) || res < 0 {
						fmt.Fprintf(comm, "No such server. Please try again\r\n")
						continue loop
					}

					return remotes[int(res)], nil
				case 0x03:
					fmt.Fprintf(comm, "\r\nGoodbye\r\n")
					return nil, errors.New("user terminated session")
				}

				buf = append(buf, b[0])
			}
		}
	}
}

// StringCallback prompts the user for a password.
func StringCallback(comm io.ReadWriter, prompt string, hide bool) (string, error) {
	if _, err := fmt.Fprintf(comm, "%s ", prompt); err != nil {
		return "", err
	}
	var buf []byte
	b := make([]byte, 1)
	var (
		n   int
		err error
	)
	for {
		if err != nil {
			return "", err
		}
		n, err = comm.Read(b)
		if n == 1 {
			switch b[0] {
			case 0x7F, 0x08:
				if len(buf) > 0 {
					buf = buf[0 : len(buf)-1]
					if !hide {
						fmt.Fprintf(comm, "\033[1D \033[1D")
					}
				}
				continue
			case '\r':
				if _, err := fmt.Fprintf(comm, "\r\n"); err != nil {
					return "", err
				}
				return string(buf), nil
			case 0x03:
				fmt.Fprintf(comm, "\r\nGoodbye\r\n")
				return "", errors.New("user terminated session")
			}
			if !hide {
				fmt.Fprintf(comm, "%s", b[0:1])
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			return "", err
		}
	}

}

// KeyboardChallenge prompts the user for keyboards challenges.
func KeyboardChallenge(comm io.ReadWriter, user, instruction string, questions []string, echos []bool) ([]string, error) {
	if len(instruction) > 0 {
		if _, err := fmt.Fprintf(comm, "%s\n", instruction); err != nil {
			return nil, err
		}
	}
	answers := make([]string, len(questions))
	for idx, question := range questions {
		if _, err := fmt.Fprintf(comm, "%s: ", question); err != nil {
			return answers, err
		}
		var buf []byte
		b := make([]byte, 1)
		var (
			n   int
			err error
		)
	outer:
		for {
			if err != nil {
				return nil, err
			}
			n, err = comm.Read(b)
			if n == 1 {
				if echos[idx] {
					if _, err := fmt.Fprintf(comm, "%s", b); err != nil {
						return answers, err
					}
				}
				switch b[0] {
				case '\r':
					if _, err := fmt.Fprintf(comm, "\r\n"); err != nil {
						return answers, err
					}
					answers[idx] = string(buf)
					break outer
				case 0x03:
					fmt.Fprintf(comm, "\r\nGoodbye\r\n")
					return nil, errors.New("user terminated session")
				}
				buf = append(buf, b[0])
			}
			if err != nil {
				return answers, err
			}
		}
	}

	return answers, nil
}
