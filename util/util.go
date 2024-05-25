// A prototype to find the attestations given a PURL. It follows the same implementation as GUAC for now.
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
)

type neighbors struct {
	occurrences  []*model.NeighborsNeighborsIsOccurrence
	hasSLSAs     []*model.NeighborsNeighborsHasSLSA
}

func GetAttestationFromPURL(purl, graphqlEndpoint string) {
	ctx := context.Background()
	httpClient := http.Client{Transport: cli.HTTPHeaderTransport(ctx, "", http.DefaultTransport)}
	gqlclient := graphql.NewClient(graphqlEndpoint, &httpClient)

	var path []string

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

	path = getAttestationPath(ctx, gqlclient, pkgNameNeighbors)

	for i, p := range path {
		fmt.Printf("%d, %+v\n", i, p)
	}

	pkgVersionNeighbors, _, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id)
	if err != nil {
		log.Fatalf("error querying for package version neighbors: %v", err)
	}

	path = getAttestationPath(ctx, gqlclient, pkgVersionNeighbors)

	for i, p := range path {
		fmt.Printf("%d, %+v\n", i, p)
	}
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
