package util

import (
	"bytes"
	"encoding/json"
	"strings"

	common "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	// slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	// slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func ParseSlsaPredicate(s *slsa02.ProvenancePredicate, slsaPredicate []model.AllSLSATreeSlsaSLSASlsaPredicateSLSAPredicate) error {
	result := make(map[string]interface{})

	for _, item := range slsaPredicate {
		keys := strings.Split(item.Key, ".")
		value := item.Value
		currMap := result

		for i, key := range keys {
			if i == len(keys)-1 {
				currMap[key] = value
			} else {
				if _, ok := currMap[key]; !ok {
					currMap[key] = make(map[string]interface{})
				}
				currMap = currMap[key].(map[string]interface{})
			}
		}
	}

	jsonData, err := json.MarshalIndent(result["slsa"], "", "  ")
	if err != nil {
		return err
	}

	// s := slsa02.ProvenancePredicate
	err = UnmarshalJSON(s, jsonData)
	if err != nil {
		return err
	}

	return nil
}

func UnmarshalJSON(s *slsa02.ProvenancePredicate, data []byte) error {
	// Replace "true" with true and "false" with false in the JSON byte slice
	data = bytes.ReplaceAll(data, []byte(`"true"`), []byte(`true`))
	data = bytes.ReplaceAll(data, []byte(`"false"`), []byte(`false`))

	type Alias slsa02.ProvenancePredicate
	aux := &struct {
		Materials map[string]common.ProvenanceMaterial `json:"materials,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal([]byte(data), &aux); err != nil {
		return err
	}

	s.Materials = make([]common.ProvenanceMaterial, len(aux.Materials))
	i := 0
	for _, m := range aux.Materials {
		s.Materials[i] = m
		i++
	}

	return nil
}
