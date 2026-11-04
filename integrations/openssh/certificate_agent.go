package openssh

import (
	"errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type CertificateAgent struct {
	agent.Agent
}

var errReadOnlyAgent = errors.New("flotte certificate agent is read-only")

func (a CertificateAgent) Add(agent.AddedKey) error     { return errReadOnlyAgent }
func (a CertificateAgent) RemoveAll() error             { return errReadOnlyAgent }
func (a CertificateAgent) Remove(_ ssh.PublicKey) error { return errReadOnlyAgent }
func (a CertificateAgent) Lock(_ []byte) error          { return errReadOnlyAgent }
func (a CertificateAgent) Unlock(_ []byte) error        { return errReadOnlyAgent }
