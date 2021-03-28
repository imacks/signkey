signutil is a program that demonstrates a use case for the `signkey` package.

Sample use case
---------------
Your application reads in a configuration file on local disk on startup. You 
do not wish the end user to modify this configuration file.

Create secret
-------------
Create a secret key on your computer. Only you should have access to this 
secret key.

```bash
# redirects output to file contoso.key
signutil -n user > contoso.key
```

The public key is embedded in the secret itself. You do not need to secure the 
public key.

```bash
signutil -s contoso.key > contoso.pub
```

Sign Configuration
------------------
Create your configuration file. To illustrate:

```bash
echo "show_trial_nag_screen = true" >> myconfig.ini
echo "force_update = true" >> myconfig.ini
```

Now sign your configuration file:

```bash
signutil -s contoso.key -f myconfig.ini > myconfig.ini.sig
```

Verify Configuration
--------------------
You hardcode the content of `contoso.pub` into your application, then distribute the 
application, `myconfig.ini` and `myconfig.ini.sig` to your end user. Your application 
should implement something similar to the code below:

```golang
package main

import (
    "io/ioutil"
    "github.com/imacks/signkey"
)

const PUBLIC_KEY = "..."

func main() {
    // application will not work without myconfig.ini or myconfig.ini.sig
    config := ioutil.ReadAll("myconfig.ini")
    signature := ioutil.ReadAll("myconfig.ini.sig")
    // this is equivilent to: signutil -p contoso.pub -g myconfig.ini.sig -f myconfig.ini
    pubkey, _ := signkey.FromPublicKey(PUBLIC_KEY)
    if err := pubkey.Verify(config, signature); err != nil {
        panic("cannot verify configuration")
    }
    // ...
}
```

If your end user modify `myconfig.ini` or `myconfig.ini.sig`, the application will not be 
able to start.

Caveats
-------
There are 2 ways to defeat this: modify the application to bypass the verification logic 
altogether, or change the value of `PUBLIC_KEY` in the application to something else. 

Countermeasures may include code obfuscation techniques, trusted crypto processor such as TPM, 
and permission settings on the Operating System level.