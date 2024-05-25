package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/in-toto/attestation-verifier/util"
	"github.com/in-toto/attestation-verifier/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

type neighbors struct {
	occurrences  []*model.NeighborsNeighborsIsOccurrence
	hasSLSAs     []*model.NeighborsNeighborsHasSLSA
}

var rootCmd = &cobra.Command{
	Use:  "ite-10-verifier",
	RunE: verify,
}

var (
	layoutPath      string
	attestationsDir string
	parametersPath  string
	graphqlEndpoint string
	purl            string
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(
		&layoutPath,
		"layout",
		"l",
		"",
		"Layout to use for verification",
	)

	rootCmd.Flags().StringVarP(
		&attestationsDir,
		"attestations-directory",
		"a",
		"",
		"Directory to load attestations from",
	)

	rootCmd.Flags().StringVar(
		&parametersPath,
		"substitute-parameters",
		"",
		"Path to JSON file containing key-value string pairs for parameter substitution in the layout",
	)

	rootCmd.Flags().StringVarP(
		&purl,
		"attestation-for",
		"p",
		"",
		"pURL for package",
	)

	rootCmd.Flags().StringVarP(
		&graphqlEndpoint,
		"attestations-from",
		"g",
		"http://localhost:8080/query",
		"endpoint used to connect to GUAC server (default: http://localhost:8080/query)",
	)

	rootCmd.MarkFlagRequired("layout")
}

func verify(cmd *cobra.Command, args []string) error {
	layout, err := verifier.LoadLayout(layoutPath)
	if err != nil {
		return err
	}

	if purl != "" {
		util.GetAttestationFromPURL(purl, graphqlEndpoint)
	}

	if attestationsDir != "" {
		dirEntries, err := os.ReadDir(attestationsDir)
		if err != nil {
			return err
		}

		attestations := map[string]*dsse.Envelope{}
		for _, e := range dirEntries {
			name := e.Name()
			ab, err := os.ReadFile(filepath.Join(attestationsDir, name))
			if err != nil {
				return err
			}
			// attestation := &attestationv1.Statement{}
			// if err := json.Unmarshal(ab, attestation); err != nil {
			// 	return err
			// }
			// encodedBytes, err := cjson.EncodeCanonical(attestation)
			// if err != nil {
			// 	return err
			// }
			// envelope := &dsse.Envelope{
			// 	Payload:     base64.StdEncoding.EncodeToString(encodedBytes),
			// 	PayloadType: "application/vnd.in-toto+json",
			// }
			envelope := &dsse.Envelope{}
			if err := json.Unmarshal(ab, envelope); err != nil {
				return err
			}

			attestations[strings.TrimSuffix(name, ".json")] = envelope
		}

		parameters := map[string]string{}
		if len(parametersPath) > 0 {
			contents, err := os.ReadFile(parametersPath)
			if err != nil {
				return err
			}

			if err := json.Unmarshal(contents, &parameters); err != nil {
				return err
			}
		}

		return verifier.Verify(layout, attestations, parameters)
	}

	// return verifier.Verify(layout, attestations, parameters)
	return err
}

func queryKnownNeighbors(ctx context.Context, gqlclient graphql.Client, subjectQueryID string) (*neighbors, []string, error) {
	collectedNeighbors := &neighbors{}
	var path []string
	neighborResponse, err := model.Neighbors(ctx, gqlclient, subjectQueryID, []model.Edge{})
	if err != nil {
		return nil, nil, fmt.Errorf("error querying neighbors: %v", err)
	}
	for _, neighbor := range neighborResponse.Neighbors {
		switch v := neighbor.(type) {
		case *model.NeighborsNeighborsHasSLSA:
			collectedNeighbors.hasSLSAs = append(collectedNeighbors.hasSLSAs, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsIsOccurrence:
			collectedNeighbors.occurrences = append(collectedNeighbors.occurrences, v)
			path = append(path, v.Id)
		default:
			continue
		}
	}
	return collectedNeighbors, path, nil
}

func getAttestationPath(ctx context.Context, gqlclient graphql.Client, collectedNeighbors *neighbors) []string {
	path := []string{}

	if len(collectedNeighbors.hasSLSAs) > 0 {
		for _, slsa := range collectedNeighbors.hasSLSAs {
			path = append(path, slsa.Slsa.Origin)
		}
	} else {
		// if there is an isOccurrence, check to see if there are slsa attestation associated with it
		for _, occurrence := range collectedNeighbors.occurrences {
			artifactFilter := &model.ArtifactSpec{
				Algorithm: &occurrence.Artifact.Algorithm,
				Digest:    &occurrence.Artifact.Digest,
			}
			artifactResponse, err := model.Artifacts(ctx, gqlclient, *artifactFilter)
			if err != nil {
				log.Printf("error querying for artifacts: %v", err)
			}
			if len(artifactResponse.Artifacts) != 1 {
				log.Printf("failed to located artifacts based on (algorithm:digest)")
			}
			neighborResponseHasSLSA, err := model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{model.EdgeArtifactHasSlsa})
			if err != nil {
				log.Printf("error querying neighbors: %v", err)
			} else {
				for _, neighborHasSLSA := range neighborResponseHasSLSA.Neighbors {
					if hasSLSA, ok := neighborHasSLSA.(*model.NeighborsNeighborsHasSLSA); ok {
						path = append(path, hasSLSA.Slsa.Origin)
					}
				}
			}
		}
	}
	return path
}
