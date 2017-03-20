package schema

import (
	"testing"

	. "github.com/zbo14/envoke/common"
	"github.com/zbo14/envoke/spec"
)

func TestSchema(t *testing.T) {
	composerId := BytesToHex(Checksum256([]byte{0}))
	publisherId := BytesToHex(Checksum256([]byte{1}))
	composition := spec.NewComposition([]string{composerId}, "B3107S", "T-034.524.680-1", "EN", "composition_title", nil, "http://www.composition.com", "")
	if err := ValidateSchema(composition, "composition"); err != nil {
		t.Error(err)
	}
	compositionId := BytesToHex(Checksum256([]byte{2}))
	transferId := BytesToHex(Checksum256([]byte{3}))
	compositionRight := spec.NewCompositionRight(compositionId, []string{publisherId}, transferId)
	if err := ValidateSchema(compositionRight, "composition_right"); err != nil {
		t.Error(err)
	}
	compositionRightId := BytesToHex(Checksum256([]byte{4}))
	publication := spec.NewPublication([]string{compositionId}, "publication_title", publisherId, []string{compositionRightId}, "")
	if err := ValidateSchema(publication, "publication"); err != nil {
		t.Error(err)
	}
	licenseeId := BytesToHex(Checksum256([]byte{6}))
	mechanicalLicense := spec.NewMechanicalLicense([]string{compositionId}, licenseeId, publisherId, []string{compositionRightId}, "2018-01-01", "2024-01-01")
	if err := ValidateSchema(mechanicalLicense, "mechanical_license"); err != nil {
		t.Error(err)
	}
}
