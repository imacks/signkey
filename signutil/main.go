package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"io"
	"io/ioutil"
	"crypto/rand"
	"encoding/base64"
	"github.com/imacks/signkey"
)

const (
	appName = "signutil"
	appDesc = "key sign and verify"
	appVer  = "1.0.0"
)

var (
	showVerAndExit bool
	verboseMode bool
	createKeyType string
	secretKeyPath string
	publicKeyPath string
	signaturePath string
	displayAllKeys bool
	entropyPath string
	infilePath string
)

func init() {
	flag.BoolVar(&showVerAndExit, "version", false, "Report version and exit")
	flag.StringVar(&createKeyType, "n", "", "Create a new signing key")
	flag.StringVar(&entropyPath, "r", "", "Path to OS entropy device")
	flag.StringVar(&secretKeyPath, "s", "", "Path to secret key, or - for stdin.")
	flag.StringVar(&publicKeyPath, "p", "", "Path to public key, or - for stdin.")
	flag.StringVar(&signaturePath, "g", "", "Path to signature file, or - for stdin.")	
	flag.StringVar(&infilePath, "f", "", "File to sign or verify")
	flag.BoolVar(&verboseMode, "v", false, "Verbose mode")

	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "%s %s () %s\n", appName, appVer, appDesc)
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintf(os.Stdout, "Usage: %s -n <type> [-r <dev>] [-v]\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "       %s -s <secret>\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "       %s -s <secret> -f <infile>\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "       %s -p <pubkey> -g <signature> -f <infile>\n", os.Args[0])
		fmt.Fprintf(os.Stdout, "       %s --version\n", os.Args[0])
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "Parameters:")
		flag.PrintDefaults()

		showMore := verboseMode
		if !showMore && len(os.Args) > 2 {
			for _, v := range os.Args[1:] {
				if v == "--verbose" || v == "-v" {
					showMore = true
					break
				}
			}
		}
		if showMore {
			fmt.Fprintln(os.Stdout, "")
			fmt.Fprintf(os.Stdout, "Notes:\n")
			fmt.Fprintf(os.Stdout, "  type must be one of: user\n")
			fmt.Fprintf(os.Stdout, "  flagset #1 create a key pair\n")
			fmt.Fprintf(os.Stdout, "  flagset #2 gets public key from secret key\n")
			fmt.Fprintf(os.Stdout, "  flagset #3 creates signature file\n")
			fmt.Fprintf(os.Stdout, "  flagset #4 verify file is signed\n")
			fmt.Fprintf(os.Stdout, "  secret key can be used to verify too\n")
			fmt.Fprintln(os.Stdout, "")
			fmt.Fprintf(os.Stdout, "Example:\n")
			fmt.Fprintf(os.Stdout, "  %s -n user > contoso.key\n", os.Args[0])
			fmt.Fprintf(os.Stdout, "  %s -s contoso.key > contoso.pub\n", os.Args[0])
			fmt.Fprintf(os.Stdout, "  echo 'lorum ipsum' > myfile.txt\n")
			fmt.Fprintf(os.Stdout, "  %s -s contoso.key -f myfile.txt > myfile.sig\n", os.Args[0])
			fmt.Fprintf(os.Stdout, "  %s -p contoso.pub -g myfile.sig -f myfile.txt | grep OK\n", os.Args[0])
			fmt.Fprintln(os.Stdout, "")
			return
		}
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintf(os.Stdout, "Use -h --verbose for more info.\n")
		return
	}
}

func main() {
	flag.Parse()
	if showVerAndExit {
		fmt.Printf("%s () %s\n", appName, appVer)
		os.Exit(0)
	}

	// create a key pair
	if createKeyType != "" {
		if secretKeyPath != "" || publicKeyPath != "" || infilePath != "" || signaturePath != "" {
			fmt.Printf("Invalid flags specified with -c.\n")
			os.Exit(1)
		}

		keytype, err := deserializeKeyType(createKeyType)
		assertFatal(err)
		kp, err := genKey(keytype, entropyPath)
		assertFatal(err)

		secret, err := kp.Secret()
		assertFatal(err)

		if verboseMode {
			pub, _ := kp.PublicKey()
			fmt.Printf("%s:%s\n", pub, secret)
		} else {
			fmt.Printf("%s\n", secret)
		}

		return
	}

	// sign file, verify file or print public key from secret key
	if secretKeyPath != "" {
		if signaturePath != "" && infilePath == "" {
			fmt.Printf("Flag -s and -g were specified but -f is not.\n")
			os.Exit(1)
		}

		if signaturePath != "" {
			// verify file
			err := verifyBySecret(infilePath, secretKeyPath, signaturePath)
			assertFatal(err)
			fmt.Printf("OK\n")
		} else if infilePath != "" {
			// sign file
			err := sign(infilePath, secretKeyPath)
			assertFatal(err)
		} else {
			// print public key from secret key
			var keyBytes []byte
			var err error
			if secretKeyPath == "-" {
				keyBytes, err = readKeyPipe()
			} else {
				keyBytes, err = readKeyFile(secretKeyPath)
			}
			assertFatal(err)
			err = printPublicKeyFromSecret(keyBytes)
			assertFatal(err)
		}
		return
	}

	// verify file
	if publicKeyPath != "" {
		if signaturePath == "" || infilePath == "" {
			fmt.Printf("Flag -p must be specified with either -f or -g.\n")
			os.Exit(1)
		}
		err := verifyByPublicKey(infilePath, publicKeyPath, signaturePath)
		assertFatal(err)
		fmt.Printf("OK\n")
		return
	}

	fmt.Printf("Invalid usage!\n")
	flag.Usage()
	os.Exit(1)
}

// printPublicKeyFromSecret gets the public key from the secret key.
func printPublicKeyFromSecret(secret []byte) error {
	kp, err := signkey.FromSecret(string(secret))
	if err != nil {
		return err
	}

	pub, _ := kp.PublicKey()
	fmt.Printf("%s\n", pub)
	//priv, _ := kp.PrivateKey()
	//fmt.Printf("%s\n", priv)
	return nil
}

// sign calculates the signature of content at path fname, using secret at path keyFile.
func sign(fname, keyFile string) error {
	if keyFile == "" {
		return fmt.Errorf("key file not specified")
	}

	var secret []byte
	var err error
	if keyFile == "-" {
        secret, err = readKeyPipe()
    } else {
        secret, err = readKeyFile(keyFile)
	}
	if err != nil {
		return err
	}

	kp, err := signkey.FromSecret(string(secret))
	if err != nil {
		return err
	}

	content, err := ioutil.ReadFile(fname)
	if err != nil {
		return err
	}

	sigraw, err := kp.Sign(content)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(sigraw))
	return nil
}

// genKey creates a new Key of type pre. Optionally specify entropy device path, e.g. /dev/urandom.
func genKey(pre signkey.KeyPrefix, entropy string) (signkey.Key, error) {
	// See if we override entropy
	ef := rand.Reader
	if entropy != "" {
		r, err := os.Open(entropy)
		if err != nil {
			return nil, err
		}
		ef = r
	}

	// Create raw seed from source or random.
	var rawSeed [signkey.SecretSize]byte
	_, err := io.ReadFull(ef, rawSeed[:]) // Or some other random source
	if err != nil {
		return nil, fmt.Errorf("cannot read from rand.Reader: %v", err)
	}

	kp, err := signkey.FromRawSecret(pre, rawSeed[:])
	if err != nil {
		return nil, err
	}

	return kp, nil
}

// verifyBySecret asserts function sign was performed. It requires the secret key at path 
// keyFile, in addition to the content signed and the signature.
func verifyBySecret(fname, keyFile, sigFile string) error {
	if keyFile == "" {
		return fmt.Errorf("key file not specified")
	}

	var secret []byte
	var err error
	if keyFile == "-" {
        secret, err = readKeyPipe()
    } else {
        secret, err = readKeyFile(keyFile)
	}
	if err != nil {
		return err
	}

	kp, err := signkey.FromSecret(string(secret))
	if err != nil {
		return err
	}

	return verify(fname, kp, sigFile)
}

// verifyByPublicKey asserts function sign was performed. It requires the public key at path 
// pubFile, in addition to the content signed and the signature.
func verifyByPublicKey(fname, pubFile, sigFile string) error {
	if pubFile == "" {
		return fmt.Errorf("key file not specified")
	}

	var pubkey []byte
	if pubFile == "-" {
	    fi, fiErr := os.Stdin.Stat()
	    if fiErr != nil {
	        return fiErr
	    }

        if (fi.Mode() & os.ModeCharDevice) != 0 {
	        return fmt.Errorf("no pipe content")
	    }

		var stdinErr error
        pubkey, stdinErr = ioutil.ReadAll(os.Stdin)
        if stdinErr != nil {
            return stdinErr
        }	
	} else {
		var ioErr error
		pubkey, ioErr = ioutil.ReadFile(pubFile)
		if ioErr != nil {
			return ioErr
		}
	}

	kp, err := signkey.FromPublicKey(string(pubkey))
	if err != nil {
		return err
	}

	return verify(fname, kp, sigFile)
}

func verify(fname string, key signkey.Key, sigFile string) error {
	if sigFile == "" {
		return fmt.Errorf("signature file required")
	}

	content, err := ioutil.ReadFile(fname)
	if err != nil {
		return err
	}

	sigEnc, err := ioutil.ReadFile(sigFile)
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(string(sigEnc))
	if err != nil {
		return err
	}

	err = key.Verify(content, sig)
	if err != nil {
		return err
	}
	return nil
}

func deserializeKeyType(keyType string) (signkey.KeyPrefix, error) {
	keyType = strings.ToLower(keyType)
	switch keyType {
	case "user":
		return signkey.UserKeyPrefix, nil
	default:
		return signkey.UnknownKeyPrefix, fmt.Errorf("invalid key type")
	}
}