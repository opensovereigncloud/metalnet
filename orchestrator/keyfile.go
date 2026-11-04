// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"mlsbond"
)

// keyFile is a debugging aid, off by default: a root-only file holding the raw key and salt of what
// is installed, so that captures can be decrypted. It is only ever read back for what dpservice
// still holds, whose keys metalnet does not get to see again after a restart.
type keyFile struct {
	path string
	sas  map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation
}

type keyFileContent struct {
	Associations []keyFileEntry `json:"associations"`
}

type keyFileEntry struct {
	VNI          uint32 `json:"vni"`
	SPI          uint32 `json:"spi"`
	Direction    string `json:"direction"`
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	Algorithm    string `json:"algorithm"`
	Key          string `json:"key"`
	Salt         string `json:"salt"`
	ESN          bool   `json:"esn"`
	ReplayWindow uint32 `json:"replay_window"`
}

func newKeyFile(path string) *keyFile {
	return &keyFile{path: path, sas: map[mlsbond.SecurityAssociationID]mlsbond.SecurityAssociation{}}
}

func (f *keyFile) add(sa mlsbond.SecurityAssociation) {
	f.sas[sa.ID] = sa
}

func (f *keyFile) remove(id mlsbond.SecurityAssociationID) {
	delete(f.sas, id)
}

// load keeps the entries of what is installed, and drops those of a dpservice that is gone. This is a
// debugging aid, so a file that cannot be read only means that what it held is not listed any more.
func (f *keyFile) load(installed map[mlsbond.SecurityAssociationID]bool) error {
	if err := f.read(installed); err != nil {
		log.Log.WithName("orchestrator").Error(err, "Starting over with the debug key file", "Path", f.path)
		clear(f.sas)
	}
	return f.write()
}

func (f *keyFile) read(installed map[mlsbond.SecurityAssociationID]bool) error {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var content keyFileContent
	if err := json.Unmarshal(data, &content); err != nil {
		return err
	}
	for _, e := range content.Associations {
		sa, err := e.securityAssociation()
		if err != nil {
			return err
		}
		if installed[sa.ID] {
			f.sas[sa.ID] = sa
		}
	}
	return nil
}

func (e *keyFileEntry) securityAssociation() (mlsbond.SecurityAssociation, error) {
	src, err1 := netip.ParseAddr(e.Src)
	dst, err2 := netip.ParseAddr(e.Dst)
	key, err3 := hex.DecodeString(e.Key)
	salt, err4 := hex.DecodeString(e.Salt)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return mlsbond.SecurityAssociation{}, err
	}
	direction := mlsbond.Egress
	if e.Direction == mlsbond.Ingress.String() {
		direction = mlsbond.Ingress
	}
	return mlsbond.SecurityAssociation{
		ID:           mlsbond.SecurityAssociationID{VNI: e.VNI, SPI: e.SPI, Direction: direction, Src: src, Dst: dst},
		Algorithm:    e.Algorithm,
		Key:          key,
		Salt:         salt,
		ESN:          e.ESN,
		ReplayWindow: e.ReplayWindow,
	}, nil
}

func compareIDs(a, b mlsbond.SecurityAssociationID) int {
	if a.VNI != b.VNI {
		return int(a.VNI) - int(b.VNI)
	}
	if c := a.Src.Compare(b.Src); c != 0 {
		return c
	}
	if c := a.Dst.Compare(b.Dst); c != 0 {
		return c
	}
	return int(a.SPI) - int(b.SPI)
}

// write replaces the file, so that a reader never sees half of it.
func (f *keyFile) write() error {
	content := keyFileContent{Associations: []keyFileEntry{}}
	for _, id := range slices.SortedFunc(maps.Keys(f.sas), compareIDs) {
		sa := f.sas[id]
		content.Associations = append(content.Associations, keyFileEntry{
			VNI: id.VNI, SPI: id.SPI, Direction: id.Direction.String(), Src: id.Src.String(), Dst: id.Dst.String(),
			Algorithm: sa.Algorithm, Key: hex.EncodeToString(sa.Key), Salt: hex.EncodeToString(sa.Salt),
			ESN: sa.ESN, ReplayWindow: sa.ReplayWindow,
		})
	}
	data, err := json.MarshalIndent(content, "", "\t")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), filepath.Base(f.path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// CreateTemp creates it root-only already
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.path)
}
