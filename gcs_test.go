package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"fmt"
	"cloud.google.com/go/storage"
	"google.golang.org/api/cloudkms/v1"
	"encoding/base64"
)

const (
	project = "tigerworks-kube"
	location = "global"

)

func TestGcs_CreateKeyRing(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)
	if err != nil {
		t.Fatal(err)
	}

	_, err = srv.CreateKeyRing(project, location, "nahid-test")
	assert.Nil(t, err)
}

func TestGcs_IsKeyRingExists(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)
	if err != nil {
		t.Fatal(err)
	}
	k,ok, err := srv.IsKeyRingExists(project, location, "nahid-test")
	assert.Nil(t,err)
	assert.Equal(t,ok,true)
	fmt.Println(k.Name)
}

func TestGcs_CreateKey(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)
	if err != nil {
		t.Fatal(err)
	}
	keyRing := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", project, location,"nahid-test")
	_, err = srv.CreateKey(keyRing, "test-key-1")
	assert.Nil(t,err)
}

func TestGcs_IsKeyExists(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)
	if err != nil {
		t.Fatal(err)
	}

	keyRing := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", project, location,"nahid-test")
	_,ok, err := srv.IsKeyExists(keyRing, "test-key-1")
	assert.Nil(t,err)
	assert.Equal(t,ok,true)
}

func TestGcs_CreateIAMServiceAccount(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.CreateIAMServiceAccount(project, "sa-nahid-test","sa-nahid-test-1234")
	assert.Nil(t,err)
}

func TestGcs_CreateCloudStorage(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)
	if err != nil {
		t.Fatal(err)
	}
	err = srv.CreateCloudStorage(project,BucketName, &storage.BucketAttrs{})
	assert.Nil(t,err)
}

func TestGcs_IsCloudStorageExists(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := srv.IsCloudStorageExists("nahid-test-bucket")
	assert.Nil(t,err)
	assert.Equal(t, ok, true)
}

func TestStoragePolicy(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)//"/home/ac/Downloads/cred/sa-nahid-test.json")
	if err != nil {
		t.Fatal(err)
	}

	p, err := srv.StorageClient.Bucket(BucketName).IAM().Policy(srv.Ctx)
	assert.Nil(t, err)
	fmt.Println(*p)

	p.Add("serviceAccount:sa-nahid-test-1234@tigerworks-kube.iam.gserviceaccount.com","roles/storage.legacyBucketReader")

	err = srv.StorageClient.Bucket(BucketName).IAM().SetPolicy(srv.Ctx, p)
	assert.Nil(t, err)

	p, err = srv.StorageClient.Bucket(BucketName).IAM().Policy(srv.Ctx)
	assert.Nil(t, err)
	fmt.Println("---------------------------------------------------------")
	fmt.Println(*p)
	// clean up
	// err = srv.StorageClient.Bucket(BucketName).Delete(srv.Ctx)
	// assert.Nil(t, err)
}

func TestPermissionBucket(t *testing.T) {
	srv, err := NewGcs("/home/ac/Downloads/cred/sa-nahid-test.json")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := srv.StorageClient.Bucket(BucketName).IAM().TestPermissions(srv.Ctx, []string{
		"storage.objects.create",
		"storage.objects.get",
		"storage.objects.list",
		"storage.objects.update",
		"storage.buckets.get",
	})

	assert.Nil(t,err)

	fmt.Println(resp)
}

func TestPermissionKey(t *testing.T) {
	srv, err := NewGcs("/home/ac/Downloads/cred/sa-nahid-test.json")
	if err != nil {
		t.Fatal(err)
	}
	keyResourceID := "projects/tigerworks-kube/locations/global/keyRings/nahid-test/cryptoKeys/vault-init"

	req := &cloudkms.TestIamPermissionsRequest{
		Permissions: []string{
			"cloudkms.cryptoKeyVersions.useToEncrypt",
			"cloudkms.cryptoKeyVersions.useToDecrypt",
		},
	}

	_, err = cloudkms.NewProjectsLocationsKeyRingsCryptoKeysService(srv.KmsService).TestIamPermissions(keyResourceID,req).Do()

	assert.Nil(t,err)

}

func TestKeyPolicy(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)//"/home/ac/Downloads/cred/sa-nahid-test.json")
	if err != nil {
		t.Fatal(err)
	}

	keySrv := cloudkms.NewProjectsLocationsKeyRingsCryptoKeysService(srv.KmsService)

	keyResourceID := "projects/tigerworks-kube/locations/global/keyRings/nahid-test/cryptoKeys/vault-init"
	// keyResourceID := "projects/tigerworks-kube/locations/global/keyRings/nahid-test/cryptoKeys/test-key-1"
	p, err := keySrv.GetIamPolicy(keyResourceID).Do()
	assert.Nil(t, err)
	fmt.Printf("%v\n",*p.Bindings[0])
}

func TestCryptoKeyEncryptDecrypt(t *testing.T) {
	srv, err := NewGcs(SAJsonFile)//"/home/ac/Downloads/cred/sa-nahid-test.json")
	if err != nil {
		t.Fatal(err)
	}
	keyResourceID := "projects/tigerworks-kube/locations/global/keyRings/nahid-test/cryptoKeys/vault-init1"

	err = srv.SetPolicyInKey("sa-nahid-test-1234@tigerworks-kube.iam.gserviceaccount.com",keyResourceID)
	assert.Nil(t, err)


	p , err := srv.KmsService.Projects.Locations.KeyRings.GetIamPolicy(keyResourceID).Do()
	assert.Nil(t, err)
	fmt.Println(p.Bindings[0])

	srv, err = NewGcs("/home/ac/Downloads/cred/sa-nahid-test.json")
	if err != nil {
		t.Fatal(err)
	}

	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte("hi")),
	}

	keySrv := cloudkms.NewProjectsLocationsKeyRingsCryptoKeysService(srv.KmsService)

	resp, err :=keySrv.Encrypt(keyResourceID, req).Do()
	assert.Nil(t,err)
	fmt.Println(resp.Name)
}
