// A prototype to find the slsa attestations.
// ./attest -l layouts/layout.yml -p pkg:guac/generic/gs://kubernetes-release/release/v1.24.1/bin/linux/arm/kubelet
package util

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/cli"
	// slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	// slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
)

type SlsaPredicate interface{}

type neighbors struct {
	occurrences []*model.NeighborsNeighborsIsOccurrence
	hasSLSAs    []*model.NeighborsNeighborsHasSLSA
}

func GetAttestationFromPURL(purl, graphqlEndpoint string) {
	ctx := context.Background()
	httpClient := http.Client{Transport: cli.HTTPHeaderTransport(ctx, "", http.DefaultTransport)}
	gqlclient := graphql.NewClient(graphqlEndpoint, &httpClient)

	pkgInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		log.Fatalf("failed to parse PURL: %v", err)
	}

	pkgQualifierFilter := []model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		qualifier := qualifier
		pkgQualifierFilter = append(pkgQualifierFilter, model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}

	pkgFilter := &model.PkgSpec{
		Type:       &pkgInput.Type,
		Namespace:  pkgInput.Namespace,
		Name:       &pkgInput.Name,
		Version:    pkgInput.Version,
		Subpath:    pkgInput.Subpath,
		Qualifiers: pkgQualifierFilter,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
	if err != nil {
		log.Fatalf("error querying for package: %v", err)
	}
	if len(pkgResponse.Packages) != 1 {
		log.Fatalf("failed to located package based on purl")
	}

	pkgNameNeighbors, _, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Id)
	if err != nil {
		log.Fatalf("error querying for package name neighbors: %v", err)
	}

	getAttestation(ctx, gqlclient, pkgNameNeighbors)

	pkgVersionNeighbors, _, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id)
	if err != nil {
		log.Fatalf("error querying for package version neighbors: %v", err)
	}

	getAttestation(ctx, gqlclient, pkgVersionNeighbors)
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

func getAttestation(ctx context.Context, gqlclient graphql.Client, collectedNeighbors *neighbors) {
	if len(collectedNeighbors.hasSLSAs) > 0 {
		for _, slsa := range collectedNeighbors.hasSLSAs {

			slsaPred := slsa02.ProvenancePredicate{}
			err := ParseSlsaPredicate(&slsaPred, slsa.Slsa.SlsaPredicate)
			if err != nil {
				log.Printf("error parsing the predicate: %v", err)
				return
			}
			log.Printf("Predicate: %+v\n", slsaPred)
			// Attestation can be created
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

						slsaPred := slsa02.ProvenancePredicate{}
						err := ParseSlsaPredicate(&slsaPred, hasSLSA.Slsa.SlsaPredicate)
						if err != nil {
							log.Printf("error parsing the predicate: %v", err)
							return
						}
						log.Printf("Predicate: %+v\n", slsaPred)
					}
				}
			}
		}
	}
}
