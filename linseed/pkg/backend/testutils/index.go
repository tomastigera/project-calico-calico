// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.
//

package testutils

import (
	"context"
	"fmt"
	"math/rand"
	"strings"

	elastic "github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

func RefreshIndex(ctx context.Context, c lmaelastic.Client, index string) error {
	logrus.WithField("index", index).Info("[TEST] Refreshing index")
	_, err := c.Backend().Refresh(index).Do(ctx)
	return err
}

func RandomClusterName() string {
	name := fmt.Sprintf("cluster-%s", RandStringRunes(8))
	logrus.WithField("name", name).Info("Using random cluster name for test")
	return name
}

func RandomTenantName() string {
	name := fmt.Sprintf("tenant-%s", RandStringRunes(8))
	logrus.WithField("name", name).Info("Using random tenant name for test")
	return name
}

func RandStringRunes(n int) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func LogIndicies(ctx context.Context, client *elastic.Client) error {
	indices, err := client.CatIndices().Do(ctx)
	if err != nil {
		return err
	}
	for _, idx := range indices {
		logrus.Infof("Index exists: %s", idx.Index)
	}
	aliases, err := client.CatAliases().Do(ctx)
	if err != nil {
		return err
	}
	for _, a := range aliases {
		logrus.Infof("Alias exists: %s -> %s", a.Alias, a.Index)
	}
	return nil
}

// CleanupSingle handles cleanup for single-index backends. It deletes all the data for a given cluster and tenant.
func CleanupSingle(ctx context.Context, client *elastic.Client, index string, i bapi.ClusterInfo) error {
	query := elastic.NewBoolQuery()
	query.Must(elastic.NewTermQuery("cluster", i.Cluster))
	if i.Tenant != "" {
		query.Must(elastic.NewTermQuery("tenant", i.Tenant))
	}
	logrus.Infof("[TEST] Deleting data for %s", i)
	_, err := client.DeleteByQuery(index).WaitForCompletion(true).Query(query).Do(ctx)
	if err != nil {
		return err
	}
	return nil
}

// CleanupMulti cleans up data for the given cluster from a multi-index backend.
func CleanupMulti(ctx context.Context, client *elastic.Client, cluster string) error {
	indices, err := client.CatIndices().Do(ctx)
	if err != nil {
		return err
	}
	for _, idx := range indices {
		if !strings.Contains(idx.Index, cluster) {
			// Skip indicies that don't match.
			continue
		}
		_, err = client.DeleteIndex(idx.Index).Do(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "not_found") {
				continue
			}
			return fmt.Errorf("error deleting index: %s", err)
		}
	}
	aliases, err := client.CatAliases().Do(ctx)
	if err != nil {
		return err
	}
	for _, a := range aliases {
		if !strings.Contains(a.Alias, cluster) {
			// Skip aliases that don't match.
			continue
		}
		_, err = client.Alias().Remove(a.Index, a.Alias).Do(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "not_found") {
				continue
			}
			return fmt.Errorf("error removing alias: %s", err)
		}
	}

	tmplResp, err := client.IndexGetIndexTemplate("*").Do(ctx)
	if err != nil {
		if !elastic.IsNotFound(err) {
			return err
		}
	} else {
		for _, tmpl := range tmplResp.IndexTemplates {
			if strings.Contains(tmpl.Name, cluster) {
				_, err = client.IndexDeleteIndexTemplate(tmpl.Name).Do(ctx)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func CleanupIndices(ctx context.Context, client *elastic.Client, singleIndex bool, index bapi.Index, i bapi.ClusterInfo) error {
	if singleIndex {
		return CleanupSingle(ctx, client, index.Index(i), i)
	} else {
		return CleanupMulti(ctx, client, i.Cluster)
	}
}
