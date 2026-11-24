package core

import (
	"github.com/marcgauthier/memarmor/internal/tpm/tpm2"
	"github.com/marcgauthier/memarmor/internal/tpm/tpm2/transport"
	"github.com/marcgauthier/memarmor/internal/tpm/tpmutil"
)

// realTPM recreates a transient storage primary for each TPM operation.
type realTPM struct{}

func (realTPM) probe() error {
	t, err := transport.OpenWithTimeout(openTPM, tpmutil.CommandTimeout)
	if err != nil {
		return err
	}
	return t.Close()
}

func (realTPM) seal(data []byte, pcrs []int) ([]byte, error) {
	t, err := transport.OpenWithTimeout(openTPM, tpmutil.CommandTimeout)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	return sealWithTPM(t, data, pcrs)
}

func sealWithTPM(t transport.TPM, data []byte, pcrs []int) ([]byte, error) {
	srk, err := createEphemeralSRK(t)
	if err != nil {
		return nil, err
	}
	defer flushTPM(t, srk.ObjectHandle)

	var digest tpm2.TPM2BDigest
	if len(pcrs) > 0 {
		digest, err = pcrPolicyDigest(t, pcrs)
		if err != nil {
			return nil, err
		}
	}
	// The TPM generates an HMAC key and derives a wrapping key. The session key stays in guarded
	// host memory throughout the operation.
	public := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			SignEncrypt:         true,
			UserWithAuth:        len(pcrs) == 0,
			NoDA:                true,
		},
		AuthPolicy: digest,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme:  tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}),
	}
	created, err := (tpm2.Create{ParentHandle: parentHandle(srk), InPublic: tpm2.New2B(public)}).Execute(t)
	if err != nil {
		return nil, err
	}
	wrappingKey, err := newBuffer(32)
	if err != nil {
		return nil, err
	}
	defer wrappingKey.discard()
	if err := deriveTPMWrappingKey(t, srk, created.OutPublic, created.OutPrivate, pcrs, wrappingKey.Data()); err != nil {
		return nil, err
	}
	wrapped, err := encryptWithCipher(data, wrappingKey.Data(), CipherXSalsa20Poly1305)
	if err != nil {
		return nil, err
	}
	return packSealedEnvelope(pcrs, wrapped, created.OutPublic.Bytes(), created.OutPrivate.Buffer), nil
}

func (realTPM) unseal(blob, dst []byte) error {
	t, err := transport.OpenWithTimeout(openTPM, tpmutil.CommandTimeout)
	if err != nil {
		return err
	}
	defer t.Close()
	return unsealWithTPM(t, blob, dst)
}

func unsealWithTPM(t transport.TPM, blob, dst []byte) error {
	pcrs, wrapped, pub, priv, err := unpackSealedEnvelope(blob)
	if err != nil {
		return err
	}
	if len(wrapped) != len(dst)+Overhead || Cipher(wrapped[0]) != CipherXSalsa20Poly1305 {
		return ErrDecryptionFailed
	}
	srk, err := createEphemeralSRK(t)
	if err != nil {
		return err
	}
	defer flushTPM(t, srk.ObjectHandle)

	wrappingKey, err := newBuffer(32)
	if err != nil {
		return err
	}
	defer wrappingKey.discard()
	public := tpm2.BytesAs2B[tpm2.TPMTPublic](pub)
	private := tpm2.TPM2BPrivate{Buffer: priv}
	if err := deriveTPMWrappingKey(t, srk, public, private, pcrs, wrappingKey.Data()); err != nil {
		return err
	}
	_, err = decrypt(wrapped, wrappingKey.Data(), dst)
	return err
}

func deriveTPMWrappingKey(t transport.TPM, srk *tpm2.CreatePrimaryResponse, pub tpm2.TPM2BPublic, priv tpm2.TPM2BPrivate, pcrs []int, dst []byte) error {
	loaded, err := (tpm2.Load{ParentHandle: parentHandle(srk), InPublic: pub, InPrivate: priv}).Execute(t)
	if err != nil {
		return err
	}
	defer flushTPM(t, loaded.ObjectHandle)

	srkPublic, err := srk.OutPublic.Contents()
	if err != nil {
		return err
	}
	salt := tpm2.Salted(srk.ObjectHandle, *srkPublic)
	encrypt := tpm2.AESEncryption(128, tpm2.EncryptOut)
	var session tpm2.Session
	var closeSession func() error
	if len(pcrs) == 0 {
		session, closeSession, err = tpm2.HMACSession(t, tpm2.TPMAlgSHA256, 32, salt, encrypt)
	} else {
		session, closeSession, err = tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 32, salt, encrypt)
	}
	if err != nil {
		return err
	}
	defer closeSession()
	if len(pcrs) > 0 {
		if err := applyPCRPolicy(t, session, pcrs); err != nil {
			return err
		}
	}
	return (tpm2.Hmac{
		Handle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   session,
		},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: []byte("memarmor/session-key-wrap/v2")},
		HashAlg: tpm2.TPMAlgSHA256,
	}).ExecuteInto(t, dst)
}

func createEphemeralSRK(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	return (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}).Execute(t)
}

func parentHandle(srk *tpm2.CreatePrimaryResponse) tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: tpm2.PasswordAuth(nil)}
}

func flushTPM(t transport.TPM, handle tpm2.TPMHandle) {
	_, _ = (tpm2.FlushContext{FlushHandle: handle}).Execute(t)
}

func pcrPolicyDigest(t transport.TPM, pcrs []int) (tpm2.TPM2BDigest, error) {
	session, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 32)
	if err != nil {
		return tpm2.TPM2BDigest{}, err
	}
	defer closeSession()
	if err := applyPCRPolicy(t, session, pcrs); err != nil {
		return tpm2.TPM2BDigest{}, err
	}
	rsp, err := (tpm2.PolicyGetDigest{PolicySession: session.Handle()}).Execute(t)
	if err != nil {
		return tpm2.TPM2BDigest{}, err
	}
	return rsp.PolicyDigest, nil
}

func applyPCRPolicy(t transport.TPM, session tpm2.Session, pcrs []int) error {
	var bitmap [3]byte
	for _, pcr := range pcrs {
		bitmap[pcr/8] |= 1 << (pcr % 8)
	}
	_, err := (tpm2.PolicyPCR{
		PolicySession: session.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
			{Hash: tpm2.TPMAlgSHA256, PCRSelect: bitmap[:]},
		}},
	}).Execute(t)
	return err
}
