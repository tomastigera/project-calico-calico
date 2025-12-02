// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package elasticsearchconfiguration

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch"
	esusers "github.com/projectcalico/calico/kube-controllers/pkg/elasticsearch/users"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
	relasticsearch "github.com/projectcalico/calico/kube-controllers/pkg/resource/elasticsearch"
	"github.com/projectcalico/calico/lma/pkg/k8s"
)

const (
	// EsUserCredentialsSchemaVersion is used in calculateUserChangeHash() to force ES users to be considered 'stale' and re-created in case there
	// is version skew between the Managed and Management clusters. The value can be bumped anytime we change something about
	// the way ES credentials work and need to re-create them.
	EsUserCredentialsSchemaVersion = "2"

	// ESGatewaySelectorLabel marks any secret containing credentials for ES gateway with this label key/value. This will allow ES gateway watch only the
	// releveant secrets it needs.
	ESGatewaySelectorLabel      = "esgateway.tigera.io/secrets"
	ESGatewaySelectorLabelValue = "credentials"
)

type reconciler struct {
	clusterName string
	// ownerReference is used to store the "owner" of this reconciler. If the owner has changed that signals the user
	// credential secrets should be rotated. It's valid to have an empty owner reference.
	ownerReference              string
	management                  bool
	managementK8sCLI            kubernetes.Interface
	managementOperatorNamespace string
	managedK8sCLI               kubernetes.Interface
	managedClientSetFactory     k8s.ClientSetFactory
	managedOperatorNamespace    string
	esK8sCLI                    relasticsearch.RESTClient
	esHash                      string
	esClientBuilder             elasticsearch.ClientBuilder
	esCLI                       elasticsearch.Client
	restartChan                 chan<- string
}

// Reconcile makes sure that the managed cluster this is running for has all the configuration needed for it's components
// to access elasticsearch. If the managed cluster this is running for is actually a management cluster, then the secret
// for the elasticsearch public certificate and the ConfigMap containing elasticsearch configuration are not copied over
func (c *reconciler) Reconcile(name types.NamespacedName) error {
	reqLogger := log.WithFields(map[string]interface{}{
		"cluster": c.clusterName,
		"key":     name,
	})
	reqLogger.Info("Reconciling Elasticsearch credentials")

	if err := c.verifyOperatorNamespaces(reqLogger); err != nil {
		return err
	}

	currentESHash, err := c.esK8sCLI.CalculateTigeraElasticsearchHash()
	if err != nil {
		return err
	}

	if c.esHash != currentESHash {
		// Only reconcile the roles if Elasticsearch has been changed in a way that may have wiped out the roles, or if
		// this is the first time Reconcile has run
		if err := c.reconcileRoles(); err != nil {
			return err
		}

		c.esHash = currentESHash
	}

	if err := c.reconcileUsers(reqLogger); err != nil {
		return err
	}

	if !c.management {
		if err := c.reconcileConfigMap(); err != nil {
			return err
		}

		if err := c.reconcileCASecrets(); err != nil {
			return err
		}
	}

	reqLogger.Info("Finished reconciling Elasticsearch credentials")

	return nil
}

func (c *reconciler) reconcileRoles() error {
	esCLI, err := c.getOrInitializeESClient()
	if err != nil {
		return err
	}

	roles := esusers.GetAuthorizationRoles(c.clusterName)
	return esCLI.CreateRoles(roles...)
}

// reconcileCASecrets copies certs from the management cluster to the managed cluster as needed for managed cluster clients to verify the certificates
// presented by servers in the management cluster. The following secrets are copied:
//
// - tigera-secure-es-gateway-http-certs-public: for clients verifying the authenticity of es-gateway
// - calico-voltron-linseed-certs-public: for clients verifying the authenticity of Voltron when talking to Linseed.
func (c *reconciler) reconcileCASecrets() error {
	// Handle the es-gateway secret.
	secret, err := c.managementK8sCLI.CoreV1().Secrets(c.managementOperatorNamespace).Get(context.Background(), resource.ESGatewayCertSecret, metav1.GetOptions{})
	if err != nil {
		return err
	}

	secret.Namespace = c.managedOperatorNamespace
	if err := resource.WriteSecretToK8s(c.managedK8sCLI, resource.CopySecret(secret)); err != nil {
		return err
	}

	// To support older Managed clusters we need to also create the tigera-secure-es-http-certs-public and tigera-secure-kb-http-certs-public secrets
	// containing the same cert so that components configured to mount the old secrets can still reach Elasticsearch and Kibana in the Management cluster.
	secret.Name = resource.ElasticsearchCertSecret
	if err := resource.WriteSecretToK8s(c.managedK8sCLI, resource.CopySecret(secret)); err != nil {
		return err
	}

	secret.Name = resource.KibanaCertSecret
	if err = resource.WriteSecretToK8s(c.managedK8sCLI, resource.CopySecret(secret)); err != nil {
		return err
	}

	// Copy the Voltron secret through as well.
	secret, err = c.managementK8sCLI.CoreV1().Secrets(c.managementOperatorNamespace).Get(context.Background(), resource.VoltronLinseedPublicCert, metav1.GetOptions{})
	if err != nil {
		return err
	}

	managedClient, err := c.managedClientSetFactory.NewClientSetForApplication(c.clusterName)
	if err != nil {
		return fmt.Errorf("failed to generate clientset for managed cluster %v from factory: %v", c.clusterName, err)
	}

	secret.Name, err = utils.FetchVersionedVoltronLinseedPublicCertName(managedClient)
	if err != nil {
		return err
	}
	secret.Namespace = c.managedOperatorNamespace
	if err := resource.WriteSecretToK8s(c.managedK8sCLI, resource.CopySecret(secret)); err != nil {
		return err
	}

	return nil
}

// verifyOperatorNamespaces makes sure that the active operator namespace has not changed in the
// managed or management cluster. If the namespace has changed then send a message to the restartChan
// so the kube-controller will restart so the new namespaces can be used.
func (c *reconciler) verifyOperatorNamespaces(reqLogger *log.Entry) error {
	m, err := utils.FetchOperatorNamespace(c.managedK8sCLI)
	if err != nil {
		return fmt.Errorf("failed to fetch the operator namespace for the %s cluster: %w", c.clusterName, err)
	}
	if m != c.managedOperatorNamespace {
		msg := fmt.Sprintf("The active operator namespace for the managed cluster %s has changed from %s to %s", c.clusterName, c.managedOperatorNamespace, m)
		reqLogger.Info(msg)
		c.restartChan <- msg
	}
	if !c.management {
		m, err := utils.FetchOperatorNamespace(c.managementK8sCLI)
		if err != nil {
			return fmt.Errorf("failed to fetch the operator namespace from the management cluster: %w", err)
		}
		if m != c.managementOperatorNamespace {
			msg := fmt.Sprintf("The active operator namespace for the managed cluster %s has changed from %s to %s", c.clusterName, c.managedOperatorNamespace, m)
			reqLogger.Info(msg)
			c.restartChan <- msg
		}
	}
	return nil
}

// reconcileUsers makes sure that all the necessary users exist for a managed cluster in elasticsearch and that the managed
// cluster has access to those users via secrets. It will also clean up users that used to be created by us but have since
// been decommissioned
func (c *reconciler) reconcileUsers(reqLogger *log.Entry) error {
	staleOrMissingPrivateUsers, staleOrMissingPublicUsers, err := c.missingOrStaleUsers()
	if err != nil {
		return err
	}

	for username, user := range staleOrMissingPrivateUsers {
		reqLogger.Infof("Creating private user %s", username)
		if err := c.createUser(username, user, true); err != nil {
			return err
		}
	}

	for username, user := range staleOrMissingPublicUsers {
		reqLogger.Infof("Creating public user %s", username)
		if err := c.createUser(username, user, false); err != nil {
			return err
		}
	}

	err = c.cleanupDecommissionedElasticsearchUsers(reqLogger)
	if err != nil {
		return err
	}

	return c.reconcileVerificationSecrets(reqLogger)
}

// reconcileVerificationSecrets ensures that the verification secrets that the Elasticsearch gateway uses exist and are
// up to date.
func (c *reconciler) reconcileVerificationSecrets(reqLogger *log.Entry) error {
	publicSecretList, err := c.managedK8sCLI.CoreV1().Secrets(c.managedOperatorNamespace).
		List(context.Background(), metav1.ListOptions{LabelSelector: ElasticsearchUserNameLabel})
	if err != nil {
		return err
	}

	verificationSecretList, err := c.managementK8sCLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).
		List(context.Background(), metav1.ListOptions{LabelSelector: ESGatewaySelectorLabel})
	if err != nil {
		return err
	}

	publicSecretMap := map[string]corev1.Secret{}
	for _, publicSecret := range publicSecretList.Items {
		username := string(publicSecret.Data["username"])

		publicSecretMap[username] = publicSecret
	}

	verifySecretMap := map[string]corev1.Secret{}
	for _, verificationSecret := range verificationSecretList.Items {
		username := string(verificationSecret.Data["username"])

		verifySecretMap[username] = verificationSecret
	}

	// Iterate through each user that's expected to have a verification secret in the tigera-elasticsearch namespace and
	// ensure that secret exists and is correct. It should match the corresponding "access" secrets in the
	// tigera-operator namespace
	_, publicEsUsers := esusers.ElasticsearchUsers(c.clusterName, c.management)
	for username, user := range publicEsUsers {
		publicSecret, exists := publicSecretMap[user.Username]
		if !exists {
			reqLogger.Warnf("No public secret for user %s", user.Username)
			continue
		}
		password := publicSecret.Data["password"]

		var verificationSecretData map[string][]byte
		// Check if a verification secret exists for the given user, if not, continue to create it.
		if verificationSecret, exists := verifySecretMap[user.Username]; exists {
			verificationSecretData = verificationSecret.Data
			// If the username matches with the current access secret in the operator namespace and verification secret
			// password matches the current access password, don't update the secret.
			if bcrypt.CompareHashAndPassword(verificationSecretData["password"], password) == nil &&
				string(verificationSecret.Data["username"]) == user.Username {
				continue
			}

			reqLogger.Infof("Password out of date for verification for user %s", user.Username)
		} else {
			reqLogger.Infof("No verification secret for user %s", user.Username)

			verificationSecretData = map[string][]byte{
				"username": []byte(user.Username),
			}
		}

		var verificationSecretName string
		if c.management {
			verificationSecretName = fmt.Sprintf("%s-gateway-verification-credentials", username)
		} else {
			verificationSecretName = fmt.Sprintf("%s-%s-gateway-verification-credentials", username, c.clusterName)
		}

		reqLogger.Infof("Creating / updating verification secret for %s", verificationSecretName)

		// Reaching this point means either there is no verification secret for the user or it's outdated. From here
		// we recalculate the hashed password and update the verification secret.
		hash, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
		if err != nil {
			reqLogger.WithError(err).Errorf("failed to generate password for %s", verificationSecretName)
		}

		verificationSecretData["password"] = hash

		// Note that we don't add the change hash label here, this is because the if there is a breaking change then
		// the change hash for the access secret in the operator namespace will force the corrections.
		labels := map[string]string{
			ElasticsearchUserNameLabel: string(username),
			ESGatewaySelectorLabel:     ESGatewaySelectorLabelValue,
		}

		err = writeUserSecret(verificationSecretName, resource.TigeraElasticsearchNamespace, labels, c.managementK8sCLI, verificationSecretData)
		if err != nil {
			reqLogger.WithError(err).Errorf("failed to create secret %s", verificationSecretName)
		}
	}

	return nil
}

func (c *reconciler) cleanupDecommissionedElasticsearchUsers(reqLogger *log.Entry) error {
	decommissionedUsers := esusers.DecommissionedElasticsearchUsers(c.clusterName)

	esCLI, err := c.getOrInitializeESClient()
	if err != nil {
		return err
	}

	allESUsers, err := esCLI.GetUsers()
	if err != nil {
		return err
	}

	// Build a lookup table so that we can figure out whether our decommissioned users exist in ES in constant time
	allESUsersLUT := map[string]any{}
	for _, esUser := range allESUsers {
		allESUsersLUT[esUser.Username] = true
	}

	errored := false

	for username, user := range decommissionedUsers {
		// Name of secrets should mirror those used in createUser function. We need to account for the fact that the
		// secrets may have come from both a "private" and "public" user list as returned by users.go
		secretName := fmt.Sprintf("%s-elasticsearch-access", username)

		reqLogger.Debugf("Deleting decommissioned secret %s/%s", c.managedOperatorNamespace, secretName)
		err = c.managedK8sCLI.CoreV1().Secrets(c.managedOperatorNamespace).Delete(context.Background(), secretName, metav1.DeleteOptions{})
		if err != nil && !strings.Contains(err.Error(), "not found") {
			errored = true
			reqLogger.WithError(err).Errorf("Error while deleting secret %s/%s (via mgd client)", c.managedOperatorNamespace, secretName)
		}

		if _, ok := allESUsersLUT[user.Username]; ok {
			reqLogger.Debugf("Deleting decommissioned user %s", username)
			for _, role := range user.Roles {
				err = esCLI.DeleteRole(role)
				if err != nil {
					errored = true
					reqLogger.WithError(err).Errorf("Error while deleting role %s", role.Name)
				}
			}
			err = esCLI.DeleteUser(user)
			if err != nil {
				errored = true
				reqLogger.WithError(err).Errorf("Error while deleting user %s", user.Username)
			}

			if c.management {
				secretName = fmt.Sprintf("%s-elasticsearch", username)
			} else {
				secretName = fmt.Sprintf("%s-%s-elasticsearch", username, c.clusterName)
			}

			if user.DirectConnection {
				secretName = fmt.Sprintf("%s-user-secret", secretName)
			} else {
				secretName = fmt.Sprintf("%s-access-gateway", secretName)
			}

			reqLogger.Debugf("Deleting decommissioned secret %s/%s", resource.TigeraElasticsearchNamespace, secretName)
			err = c.managementK8sCLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Delete(context.Background(), secretName, metav1.DeleteOptions{})
			if err != nil && !strings.Contains(err.Error(), "not found") {
				errored = true
				reqLogger.WithError(err).Errorf("Error while deleting secret %s/%s (via mgmt client)", resource.TigeraElasticsearchNamespace, secretName)
			}
		}

		// These name patterns need to match those in the reconcileVerificationSecrets function.
		var verificationSecretName string
		if c.management {
			verificationSecretName = fmt.Sprintf("%s-gateway-verification-credentials", username)
		} else {
			verificationSecretName = fmt.Sprintf("%s-%s-gateway-verification-credentials", username, c.clusterName)
		}

		reqLogger.Debugf("Deleting decommissioned secret %s/%s", resource.TigeraElasticsearchNamespace, verificationSecretName)
		err = c.managementK8sCLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).Delete(context.Background(), verificationSecretName, metav1.DeleteOptions{})
		if err != nil && !strings.Contains(err.Error(), "not found") {
			errored = true
			reqLogger.WithError(err).Errorf("Error while deleting verification secret %s/%s (via mgmt client)", resource.TigeraElasticsearchNamespace, verificationSecretName)
		}
	}

	if errored {
		return fmt.Errorf("one or more errors occurred while deleting decommissioned users")
	}

	return nil
}

// createUser creates the given Elasticsearch user in Elasticsearch if passed a private user and creates a secret containing that users credentials.
// Secrets containing private user credentials (real Elasticsearch credentials) can only be created in the Elasticsearch namespace
// in the Management cluster. Secrets containing public user credentials are created in the Operator namespace in either the Managed or
// Management cluster, as well as in the Elasticsearch namespace in the Management cluster. These public users are not actual Elasticsearch users.
// They are used by ES Gateway to authenticate components attempting to communicate with Elasticsearch and to then swap in credentials for real Elasticsearch users.
func (c *reconciler) createUser(username esusers.ElasticsearchUserName, esUser elasticsearch.User, elasticsearchUser bool) error {
	esUser.Password = utils.GeneratePassword(32)
	changeHash, err := c.calculateUserChangeHash(esUser)
	if err != nil {
		return err
	}

	name := fmt.Sprintf("%s-elasticsearch-access", string(username))
	data := map[string][]byte{
		"username": []byte(esUser.Username),
		"password": []byte(esUser.Password),
		// Allows consumers of this secret to make decisions based on the cluster associated with requests.
		"cluster_name": []byte(c.clusterName),
	}

	if elasticsearchUser {
		// Only private users are created in Elasticsearch.
		esCLI, err := c.getOrInitializeESClient()
		if err != nil {
			return err
		}
		if err := esCLI.CreateUser(esUser); err != nil {
			return err
		}

		if c.management {
			name = fmt.Sprintf("%s-elasticsearch", string(username))
		} else {
			name = fmt.Sprintf("%s-%s-elasticsearch", string(username), c.clusterName)
		}

		if esUser.DirectConnection {
			name = fmt.Sprintf("%s-user-secret", name)
		} else {
			name = fmt.Sprintf("%s-access-gateway", name)
		}

		// Set required labels for the user secret.
		labels := map[string]string{
			UserChangeHashLabel:        changeHash,
			ElasticsearchUserNameLabel: string(username),
			ESGatewaySelectorLabel:     ESGatewaySelectorLabelValue,
		}

		// Create the user secret in the Management cluster Elasticsearch namespace.
		return writeUserSecret(name, resource.TigeraElasticsearchNamespace, labels, c.managementK8sCLI, data)
	}

	// Set required labels for the user secret. We leave out the ES Gateway label initially here because the first write
	// below is to the Operator namespace, which doesn't require this label.
	labels := map[string]string{
		UserChangeHashLabel:        changeHash,
		ElasticsearchUserNameLabel: string(username),
	}

	return writeUserSecret(name, c.managedOperatorNamespace, labels, c.managedK8sCLI, data)
}

// missingOrStaleUsers returns 2 maps, the first containing private users and the second containing public users that are
// missing from the cluster or have mismatched elasticsearch hashes (indicating that elasticsearch changed in a way that requires user credential recreation).
func (c *reconciler) missingOrStaleUsers() (map[esusers.ElasticsearchUserName]elasticsearch.User, map[esusers.ElasticsearchUserName]elasticsearch.User, error) {
	privateEsUsers, publicEsUsers := esusers.ElasticsearchUsers(c.clusterName, c.management)

	publicSecretsList, err := c.managedK8sCLI.CoreV1().Secrets(c.managedOperatorNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: ElasticsearchUserNameLabel})
	if err != nil {
		return nil, nil, err
	}

	privateSecretsList, err := c.managementK8sCLI.CoreV1().Secrets(resource.TigeraElasticsearchNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: ElasticsearchUserNameLabel})
	if err != nil {
		return nil, nil, err
	}

	for _, secret := range publicSecretsList.Items {
		username := esusers.ElasticsearchUserName(secret.Labels[ElasticsearchUserNameLabel])
		if user, exists := publicEsUsers[username]; exists {
			userHash, err := c.calculateUserChangeHash(user)
			if err != nil {
				return nil, nil, err
			}
			log.WithField("userName", user.Username).WithField("userHash", userHash).WithField("secretHash", secret.Labels[UserChangeHashLabel]).Debug("public user comparison")
			if secret.Labels[UserChangeHashLabel] == userHash {
				delete(publicEsUsers, username)
			}
		}
	}

	for _, secret := range privateSecretsList.Items {
		if strings.HasSuffix(secret.Name, "gateway-verification-credentials") {
			continue
		}

		username := esusers.ElasticsearchUserName(secret.Labels[ElasticsearchUserNameLabel])
		if user, exists := privateEsUsers[username]; exists {
			userHash, err := c.calculateUserChangeHash(user)
			if err != nil {
				return nil, nil, err
			}
			log.WithField("userName", user.Username).WithField("userHash", userHash).WithField("secretHash", secret.Labels[UserChangeHashLabel]).Debug("private user comparison")
			if secret.Labels[UserChangeHashLabel] == userHash {
				delete(privateEsUsers, username)
			}
		}
	}
	log.WithField("privateUsers", privateEsUsers).WithField("publicUsers", publicEsUsers).Debug("missing users")
	return privateEsUsers, publicEsUsers, nil
}

func (c *reconciler) calculateUserChangeHash(user elasticsearch.User) (string, error) {
	obj := []interface{}{c.esHash, c.ownerReference, user.FullName, EsUserCredentialsSchemaVersion}
	for _, role := range user.Roles {
		obj = append(obj, role.Name)
		if role.Definition != nil {
			obj = append(obj, *role.Definition)
		}
	}
	return utils.GenerateTruncatedHash(obj, 24)
}

func (c *reconciler) getOrInitializeESClient() (elasticsearch.Client, error) {
	if c.esCLI == nil {
		var err error

		c.esCLI, err = c.esClientBuilder.Build()
		if err != nil {
			return nil, err
		}
	}

	return c.esCLI, nil
}

func writeUserSecret(name, namespace string, labels map[string]string, client kubernetes.Interface, data map[string][]byte) error {
	return resource.WriteSecretToK8s(client, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Data: data,
	})
}
