package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"

	"log"

	"cloud.google.com/go/storage"
	"github.com/appscode/kutil/tools/certstore"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/cert"
)

var (
	KeyRingName        = "nahid-test"
	KeyName            = "vault-init2"
	BucketName         = "vault-test-bucket"
	ProjectID          = "tigerworks-kube"
	SAJsonFile         = "/home/ac/Downloads/cred/gc-sa-vault-admin.json"
	ServiceAccountName = "sa-nahid-test"
	ServiceAccountID   = "sa-nahid-test-1234"
)

func main() {
	appFs := afero.NewMemMapFs()
	certStr, err := certstore.NewCertStore(appFs, "./pki")
	if err != nil {
		log.Fatal(err)
	}

	err = certStr.NewCA()
	if err != nil {
		log.Fatal(err)
	}
	ca := certStr.CACert()
	crt, key, err := certStr.NewServerCertPair("server", cert.AltNames{
		DNSNames: []string{
			"vault",
			"vault.default.svc.cluster.local",
			"localhost",
		},
		IPs: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	})

	gcs, err := NewGcs(SAJsonFile)
	if err != nil {
		log.Fatal(err)
	}

	// create key ring
	kRing, found, _ := gcs.IsKeyRingExists(ProjectID, "global", KeyRingName)
	if !found {
		kRing, err = gcs.CreateKeyRing(ProjectID, "global", KeyRingName)
		if err != nil {
			log.Fatal(err)
		}
	}

	//create key
	crytpoKey, found, _ := gcs.IsKeyExists(kRing.Name, KeyName)
	if !found {
		crytpoKey, err = gcs.CreateKey(kRing.Name, KeyName)
		if err != nil {
			log.Fatal(err)
		}
	}

	// create storage
	found, _ = gcs.IsCloudStorageExists(BucketName)
	if !found {
		err = gcs.CreateCloudStorage(ProjectID, BucketName, &storage.BucketAttrs{})
		if err != nil {
			log.Fatal(err)
		}
	}

	// create service account

	sa, found, _ := gcs.IsIAMServiceAccountExists(ProjectID, fmt.Sprintf("%s@%s.iam.gserviceaccount.com",ServiceAccountID,ProjectID))
	if !found {
		sa, err = gcs.CreateIAMServiceAccount(ProjectID, ServiceAccountName, ServiceAccountID)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("service account(%s) already exists\n",sa.Email)
	}

	// grant access
	err = gcs.SetPolicyInKey(sa.Email, crytpoKey.Name)
	if err != nil {
		log.Fatal(err)
	}
	err = gcs.SetPolicyInStorageBucket(sa.Email, BucketName)
	if err != nil {
		log.Fatal(err)
	}

	var objects []runtime.Object
	objects = append(objects, getSecret(ca, crt, key), getConfigMap("https://vault.default.svc", BucketName, crytpoKey.Name))
	data, err := GenerateYmals(objects)
	err = ioutil.WriteFile("vault-config.yaml", data, 777)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("--------------------------------------------------------------------------")
	fmt.Println("Project ID:", ProjectID)
	fmt.Println("Storage Bucket Name:", BucketName)
	fmt.Println("Service account email:", sa.Email)
	fmt.Println("KMS key ID:", crytpoKey.Name)
}

func GenerateYmals(objects []runtime.Object) ([]byte, error) {
	mediaType := "application/yaml"
	info, ok := runtime.SerializerInfoForMediaType(clientsetscheme.Codecs.SupportedMediaTypes(), mediaType)
	if !ok {
		return nil, errors.Errorf("unsupported media type %q", mediaType)
	}
	codec := versioning.NewCodecForScheme(clientsetscheme.Scheme, info.Serializer, info.Serializer, nil, nil)

	var buf bytes.Buffer
	for i, obj := range objects {
		if i > 0 {
			buf.WriteString("---\n")
		}
		err := codec.Encode(obj, &buf)
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func getSecret(ca, crt, key []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vault",
		},
		Data: map[string][]byte{
			"ca.crt":     ca,
			"server.crt": crt,
			"server.key": key,
		},
	}
}

func getConfigMap(apiAddr, gcsBucketName, kmsKeyID string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vault",
		},
		Data: map[string]string{
			"api-addr":        apiAddr,
			"gcs-bucket-name": gcsBucketName,
			"kms-key-id":      kmsKeyID,
		},
	}
}
