package cmd

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/projectcalico/calico/licensing/client"
	"github.com/projectcalico/calico/licensing/client/features"
	"github.com/projectcalico/calico/licensing/datastore"
)

var (
	claims client.LicenseClaims

	customerFlag, expFlag, nodeFlag, graceFlag, debugFlag, useDBFlag, privKeyPathFlag, certPathFlag, packageFlags *pflag.FlagSet

	// Tigera private key location.
	// Defaults to "./tigera.io_private_key.pem"
	privKeyPath string

	// Tigera license signing certificate path.
	// Defaults to "./tigera.io_certificate.pem"
	certPath string

	licensePackage string

	debug = false

	exp string

	nodes int

	useDB bool
)

func init() {
	customerFlag = GenerateLicenseCmd.PersistentFlags()
	customerFlag.StringVarP(&claims.Customer, "customer", "c", "", "Customer name")

	expFlag = GenerateLicenseCmd.PersistentFlags()
	expFlag.StringVarP(&exp, "expiry", "e", "", "License expiration date in MM/DD/YYYY format. Expires at the end of the day cluster local timezone.")

	nodeFlag = GenerateLicenseCmd.PersistentFlags()
	nodeFlag.IntVarP(&nodes, "nodes", "n", 0, "Number of nodes customer is licensed for. If not specified, it'll be an unlimited nodes license.")

	graceFlag = GenerateLicenseCmd.PersistentFlags()
	graceFlag.IntVarP(&claims.GracePeriod, "graceperiod", "g", 90, "Number of days the cluster will keep working after the license expires")

	debugFlag = GenerateLicenseCmd.PersistentFlags()
	debugFlag.BoolVar(&debug, "debug", false, "Print debug logs while generating this license")

	privKeyPathFlag = GenerateLicenseCmd.PersistentFlags()
	privKeyPathFlag.StringVar(&privKeyPath, "signing-key", "./tigera.io_private_key.pem", "Private key path to sign the license content")

	certPathFlag = GenerateLicenseCmd.PersistentFlags()
	certPathFlag.StringVar(&certPath, "certificate", "./tigera.io_certificate.pem", "Licensing intermediate certificate path")

	packageFlags = GenerateLicenseCmd.PersistentFlags()
	packageFlags.StringVarP(&licensePackage, "package", "p", features.Enterprise, "License Package and feature selection to be assigned to a license")

	useDBFlag = GenerateLicenseCmd.PersistentFlags()
	useDBFlag.BoolVarP(&useDB, "useDB", "u", true, "Connect with the password database while generating this license")

	_ = GenerateLicenseCmd.MarkPersistentFlagRequired("customer")
	_ = GenerateLicenseCmd.MarkPersistentFlagRequired("expiry")
}

var GenerateLicenseCmd = &cobra.Command{
	Use:        "generate",
	Aliases:    []string{"gen", "gen-lic", "generate-license", "make-me-a-license"},
	SuggestFor: []string{"gen", "generat", "generate-license"},
	Short:      "Generate Calico Enterprise license file and store the fields in the database",
	Run: func(cmd *cobra.Command, args []string) {
		// Lower case customer name for consistency.
		claims.Customer = strings.ToLower(claims.Customer)

		// Replace spaces with '-' so the generated file name doesn't have spaces in the name.
		claims.Customer = strings.ReplaceAll(claims.Customer, " ", "-")

		// Parse expiration date into time format and set it to end of the day for that date.
		claims.Expiry = parseExpiryDate(exp)

		// Generate a random UUID for the licenseID.
		claims.LicenseID = uuid.NewString()

		// If the nodes flag is specified then set the value here
		// else leave it to nil (default) - which means unlimited nodes license.
		if nodeFlag.Changed("nodes") {
			claims.Nodes = &nodes
		}

		// License claims version 1.
		claims.Version = "1"

		// License all the features in accordance to a license package.
		if !features.IsValidPackageName(licensePackage) {
			log.Fatalf("[ERROR] License Package must match one of %#v", features.PackageNames)
		}

		switch licensePackage {
		case features.Enterprise:
			claims.Features = strings.Split(licensePackage, "|")
		}

		// This might be used in future. Or it could be used for debugging.
		claims.IssuedAt = jwt.NewNumericDate(time.Now().UTC())

		if len(claims.Customer) < 3 {
			log.Fatal("[ERROR] Customer name must be at least 3 characters long")
		}

		nodeCountStr := ""
		if claims.Nodes == nil {
			nodeCountStr = "Unlimited (site license)"
		} else {
			nodeCountStr = strconv.Itoa(*claims.Nodes)
		}

		// We don't set the CheckinInterval so it's an offline license since we don't have call-home server in v2.1.
		// This will be a flag when we have the licensing server, with default check-in interval set to a week,
		// the unit of this variable is hours.
		checkinIntervalStr := ""
		if claims.CheckinInterval == nil {
			checkinIntervalStr = "Offline license"
		} else {
			checkinIntervalStr = fmt.Sprintf("%d Hours", *claims.CheckinInterval)
		}

		fmt.Println("Confirm the license information:")
		fmt.Println("_________________________________________________________________________")
		fmt.Printf("Customer name:                  %s\n", claims.Customer)
		fmt.Printf("Number of nodes:                %s\n", nodeCountStr)
		fmt.Printf("License term expiration date:   %v\n", claims.Expiry.Time())
		fmt.Printf("Features (License Package):     %s\n", claims.Features)
		fmt.Printf("Checkin interval:               %s\n", checkinIntervalStr)
		fmt.Printf("Grace period (days):            %d\n", claims.GracePeriod)
		fmt.Printf("License ID (auto-generated):    %s\n", claims.LicenseID)
		fmt.Printf("Use DB:                         %v\n", useDB)
		fmt.Println("________________________________________________________________________")
		fmt.Println("\nIs the license information correct? [y/N]")

		var valid string
		if _, err := fmt.Scanf("%s", &valid); err != nil {
			log.Fatalf("error reading response %q : %v", valid, err)
		}

		if strings.ToLower(valid) != "y" {
			os.Exit(1)
		}

		absPrivKeyPath, err := filepath.Abs(privKeyPath)
		if err != nil {
			log.Fatalf("error getting the absolute path for %q : %v", privKeyPath, err)
		}

		absCertPath, err := filepath.Abs(certPath)
		if err != nil {
			log.Fatalf("error getting the absolute path for %q : %v", certPath, err)
		}

		lic, err := client.GenerateLicenseFromClaims(claims, absPrivKeyPath, absCertPath)
		if err != nil {
			log.Fatalf("error generating license from claims: %v", err)
		}

		var licenseID int64
		var db *datastore.DB
		if useDB {
			if debug {
				fmt.Printf("Connecting to: %q\n", datastore.DSN)
			}

			// Store the license in the license database.
			db, err = datastore.NewDB(datastore.DSN)
			if err != nil {
				log.Fatalf("error connecting to license database: %v", err)
			}

			// Find or create the Company entry for the license.
			companyID, err := db.GetCompanyIdByName(claims.Customer)
			if errors.Is(err, sql.ErrNoRows) {
				// Confirm creation of company with the user in case they mistyped.
				fmt.Printf("Customer '%s' not found in company database.  Create new company? [y/N]\n", claims.Customer)
				var create string
				if _, err := fmt.Scanf("%s", &create); err != nil {
					log.Fatalf("error reading response %q : %v", create, err)
				}

				if strings.ToLower(create) != "y" {
					os.Exit(1)
				}

				companyID, err = db.CreateCompany(claims.Customer)
				if err != nil {
					log.Fatalf("error creating company: %v", err)
				}
			} else if err != nil {
				log.Fatalf("error looking up company: %v", err)
			}

			// Save the license in the DB.
			licenseID, err = db.CreateLicense(lic, companyID, &claims)
			if err != nil {
				log.Fatalf("error saving license to database: %v", err)
			}
		}

		// License successfully stored in database: emit yaml file.
		err = WriteYAML(*lic, claims.Customer)
		if err != nil {
			// Remove the license from the database (leave the company around).
			cleanupErr := db.DeleteLicense(licenseID)
			if cleanupErr != nil {
				log.Fatalf("error creating the license file: %v and error cleaning license up from database: %v",
					err,
					cleanupErr,
				)
			}
			log.Fatalf("error creating the license file: %v", err)
		}

		if debug {
			spew.Dump(claims)
		}
	},
}

func parseExpiryDate(dateStr string) *jwt.NumericDate {
	expSlice := strings.Split(dateStr, "/")
	if len(expSlice) != 3 {
		log.Fatal("[ERROR] expiration date must be in MM/DD/YYYY format")
	}
	yyyy, err := strconv.Atoi(expSlice[2])
	if err != nil {
		log.Fatalf("[ERROR] invalid year\n")
	}

	mm, err := strconv.Atoi(expSlice[0])
	if err != nil || mm < 1 || mm > 12 {
		log.Fatalf("[ERROR] invalid month\n")
	}

	dd, err := strconv.Atoi(expSlice[1])
	if err != nil || dd < 1 || dd > 31 {
		log.Fatalf("[ERROR] invalid date\n")
	}

	if yyyy < time.Now().Year() {
		log.Fatalf("[ERROR] Year cannot be in the past! Unless you're a time traveller, in which case go back in time and stop me from writing this validation :P")
	}

	return jwt.NewNumericDate(time.Date(yyyy, time.Month(mm), dd, 23, 59, 59, 999999999, time.Local))
}
