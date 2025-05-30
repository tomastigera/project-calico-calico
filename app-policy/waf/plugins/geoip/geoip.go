package geoip

import (
	_ "embed"
	"fmt"

	geo "github.com/corazawaf/coraza-geoip"
	log "github.com/sirupsen/logrus"
)

func GeoIPPluginInitializerFn(dbFilePath, dbFileType string) func() error {
	return func() error {
		log.WithFields(log.Fields{
			"dbFilePath": dbFilePath,
			"dbFileType": dbFileType,
		}).Info("Registering GeoIP database")
		if dbFilePath == "" && dbFileType == "" {
			log.Warn("GeoIP database path is empty, skipping registration")
			return nil
		}

		switch dbFileType {
		case "city", "country":
		default:
			return fmt.Errorf("unsupported GeoIP database type specified: '%s'", dbFileType)
		}

		if dbFilePath != "" {
			err := geo.RegisterGeoDatabaseFromFile(dbFilePath, dbFileType)
			if err != nil {
				return fmt.Errorf("error registering GeoIP database: %s", err)
			}
		}

		return nil
	}
}
