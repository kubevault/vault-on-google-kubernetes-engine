package main

import (
	"context"
	"io/ioutil"

	"fmt"
	"path/filepath"

	iamadmin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/storage"
	"log"
	"github.com/pkg/errors"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
	adminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
)

type Gcs struct {
	SAJsonFile    string
	KmsService    *cloudkms.Service
	StorageClient *storage.Client
	IamClient     *iamadmin.IamClient
	BucketName    string
	Ctx           context.Context
}

func NewGcs(saJsonFile string) (*Gcs, error) {
	var (
		jwtConfig *jwt.Config
		err       error
	)

	g := &Gcs{}
	g.Ctx = context.Background()

	if saJsonFile != "" {
		sa, err := ioutil.ReadFile(saJsonFile)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load service account json file %s", saJsonFile)
		}

		jwtConfig, err = google.JWTConfigFromJSON(sa, cloudkms.CloudPlatformScope, "https://www.googleapis.com/auth/iam")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create JWT config from service account json file %s", saJsonFile)
		}
	}

	client := jwtConfig.Client(g.Ctx)

	g.KmsService, err = cloudkms.New(client)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create kms service")
	}

	g.IamClient, err = iamadmin.NewIamClient(g.Ctx, option.WithTokenSource(jwtConfig.TokenSource(g.Ctx)))
	if err != nil {
		return nil, errors.Wrap(err, "unable to create iam client")
	}

	g.StorageClient, err = storage.NewClient(g.Ctx, option.WithTokenSource(jwtConfig.TokenSource(g.Ctx)))
	if err != nil {
		return nil, errors.Wrap(err, "unable to create google cloud storage")
	}

	return g, nil
}

func (g *Gcs) IsKeyRingExists(projectID, location, keyRingID string) (*cloudkms.KeyRing, bool, error) {
	name := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, location, keyRingID)
	req := cloudkms.NewProjectsLocationsKeyRingsService(g.KmsService).Get(name)
	kRing, err := req.Do()
	if err != nil {
		return nil, false, err
	}

	return kRing, true, nil
}

// ref: https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings/create
func (g *Gcs) CreateKeyRing(projectID, location, keyRingID string) (*cloudkms.KeyRing, error) {
	keyRingSrv := cloudkms.NewProjectsLocationsKeyRingsService(g.KmsService)

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)

	log.Printf("Creating keyRing(%s)...\n", filepath.Join(parent, "keyRings", keyRingID))

	keyRing := &cloudkms.KeyRing{
		Name: filepath.Join(parent, "keyRings", keyRingID),
	}

	req := keyRingSrv.Create(parent, keyRing)
	req.KeyRingId(keyRingID)

	kRing, err := req.Do()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to create keyring(%s)", keyRingID)
	}
	log.Printf("keyRing(%s) is created\n", kRing.Name)

	return kRing, nil
}

func (g *Gcs) IsKeyExists(keyRing, keyID string) (*cloudkms.CryptoKey, bool, error) {
	name := fmt.Sprintf("%s/cryptoKeys/%s", keyRing, keyID)
	req := cloudkms.NewProjectsLocationsKeyRingsCryptoKeysService(g.KmsService).Get(name)
	key, err := req.Do()
	if err != nil {
		return nil, false, err
	}

	return key, true, nil
}

// ref: https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/create
//
// ref: https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings#KeyRing.FIELDS.name
// keyRing format: projects/{project_id}/locations/{location}/keyRings/{keyRingId}
func (g *Gcs) CreateKey(keyRing, keyID string) (*cloudkms.CryptoKey, error) {
	log.Printf("Creating key(%s) in keyRing(%s):", keyID, keyRing)
	keySrv := cloudkms.NewProjectsLocationsKeyRingsCryptoKeysService(g.KmsService)

	cryptoKey := &cloudkms.CryptoKey{
		Purpose: "ENCRYPT_DECRYPT",
	}

	req := keySrv.Create(keyRing, cryptoKey)
	req.CryptoKeyId(keyID)
	k, err := req.Do()
	if err != nil {
		return nil, errors.Wrap(err, "unable to create crypto key")
	}
	log.Printf("key(%s) is created", k.Name)
	return k, err
}

// https://cloud.google.com/kms/docs/reference/permissions-and-roles
//
// member: serviceAccount:vault-server@${PROJECT_ID}.iam.gserviceaccount.com \
// role: roles/cloudkms.cryptoKeyEncrypterDecrypter \
func (g *Gcs) SetPolicyInKey(saEmail, keyResourceID string) error {
	log.Printf("Setting policy in crypto key for service account(%s)...", saEmail)
	policy, err := g.KmsService.Projects.Locations.KeyRings.CryptoKeys.GetIamPolicy(keyResourceID).Do()
	if err!=nil {
		return errors.Wrap(err, "unable to get policy")
	}

	policy.Bindings  = append(policy.Bindings, &cloudkms.Binding{
		Role: "roles/cloudkms.cryptoKeyEncrypterDecrypter",
		Members: []string{
			fmt.Sprintf("serviceAccount:%s", saEmail),
		},
	})
	_, err = g.KmsService.Projects.Locations.KeyRings.CryptoKeys.SetIamPolicy(
		keyResourceID, &cloudkms.SetIamPolicyRequest{
			Policy: policy,
		}).Do()
	if err != nil {
		return errors.Wrapf(err, "unable to set policy in crypto key for service account(%s)", saEmail)
	}

	log.Printf("Setting policy in crypto key for service account(%s) is successful", saEmail)

	return nil
}

// name formate : projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}
func (g *Gcs) IsIAMServiceAccountExists(projectID, saAccountID string) (*adminpb.ServiceAccount, bool, error) {
	req := &adminpb.GetServiceAccountRequest{

		Name: fmt.Sprintf("projects/-/serviceAccounts/%s",saAccountID),
	}

	sa, err := g.IamClient.GetServiceAccount(g.Ctx, req)
	if err!=nil {
		log.Println("error:", err)
		return nil, false, err
	}

	return sa, true, nil
}

// ref: https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/create
func (g *Gcs) CreateIAMServiceAccount(projectID, saName, acID string) (*adminpb.ServiceAccount, error) {
	log.Printf("Creating service account(%s)...\n", saName)
	saReq := &adminpb.CreateServiceAccountRequest{
		Name:      filepath.Join("projects", projectID),
		AccountId: acID,
		ServiceAccount: &adminpb.ServiceAccount{
			DisplayName: saName,
		},
	}

	sa, err := g.IamClient.CreateServiceAccount(g.Ctx, saReq)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create service account")
	}
	log.Printf("Service account is created: %v \n", *sa)
	return sa, nil
}

// ref:
//	  https://cloud.google.com/storage/docs/json_api/v1/buckets
//    https://cloud.google.com/storage/docs/creating-buckets
func (g *Gcs) CreateCloudStorage(projectID, bucketName string, bucketAttr *storage.BucketAttrs) error {
	log.Printf("Creating bucket(%s)....", bucketName)
	err := g.StorageClient.Bucket(bucketName).Create(g.Ctx, projectID, bucketAttr)
	if err != nil {
		return errors.Wrapf(err, "unable to create bucket(%s)", bucketName)
	}
	return nil
}

func (g *Gcs) IsCloudStorageExists(bucketName string) (bool, error) {
	_, err := g.StorageClient.Bucket(bucketName).Attrs(g.Ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ref: https://cloud.google.com/storage/docs/access-control/iam-roles
// role:
// 	objectAdmin
//  legacyBucketReader
func (g *Gcs) SetPolicyInStorageBucket(saEmail, bucketName string) error {
	log.Printf("Setting policy in storage bucket for service account(%s)...", saEmail)

	p, err := g.StorageClient.Bucket(bucketName).IAM().Policy(g.Ctx)
	if err != nil {
		return errors.Wrap(err, "unable to get policy")
	}

	member := fmt.Sprintf("serviceAccount:%s", saEmail)

	p.Add(member, "roles/storage.objectAdmin")
	p.Add(member, "roles/storage.legacyBucketReader")

	err = g.StorageClient.Bucket(bucketName).IAM().SetPolicy(g.Ctx, p)
	if err != nil {
		return errors.Wrapf(err, "unable to set policy in storage bucket for service account(%s)", saEmail)
	}

	log.Printf("Setting policy in storage bucket for service account(%s) is successful", saEmail)

	return nil
}
