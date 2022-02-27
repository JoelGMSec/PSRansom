<p align="center"><img width=750 alt="PSRansom" src="https://github.com/JoelGMSec/PSRansom/blob/main/PSRansom.png"></p>

# PSRansom
**PSRansom** is a PowerShell Ransomware Simulator with C2 Server capabilities. This tool helps you simulate encryption process of a generic ransomware in any system on any system with PowerShell installed on it. Thanks to the integrated C2 server, you can exfiltrate files and receive client information via HTTP. 

All communication between the two elements is encrypted or encoded so as to be undetected by traffic inspection mechanisms, although at no time is HTTPS used at any time.

# Requirements
- PowerShell 4.0 or greater


# Download
It is recommended to clone the complete repository or download the zip file.
You can do this by running the following command:
```
git clone https://github.com/JoelGMSec/PSRansom
```


# Usage
```
.\PSRansom -h

  ____  ____  ____
 |  _ \/ ___||  _ \ __ _ _ __  ___  ___  _ __ ___
 | |_) \___ \| |_) / _' | '_ \/ __|/ _ \| '_ ' _ \
 |  __/ ___) |  _ < (_| | | | \__ \ (_) | | | | | |
 |_|   |____/|_| \_\__,_|_| |_|___/\___/|_| |_| |_|

  ----------------- by @JoelGMSec ----------------

 Info:  This tool helps you simulate encryption process of a
        generic ransomware in PowerShell with C2 capabilities

 Usage: .\RansomShell.ps1 -e Directory -s C2Server -p C2Port
          Encrypt all files & sends recovery key to C2Server
          Use -x to exfiltrate and decrypt files on C2Server

        .\RansomShell.ps1 -d Directory -k RecoveryKey
          Decrypt all files with recovery key string

 Warning: All info will be sent to the C2Server without any encryption
          You need previously generated recovery key to retrieve files

```

### The detailed guide of use can be found at the following link:

https://darkbyte.net/psransom-simulando-un-ransomware-generico-con-powershell


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
This tool has been created and designed from scratch by Joel Gámez Molina // @JoelGMSec


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can find me on Twitter as [@JoelGMSec](https://twitter.com/JoelGMSec) and on my blog [darkbyte.net](https://darkbyte.net).


# Support
You can support my work buying me a coffee:

[<img width=250 alt="buymeacoffe" src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png">](https://www.buymeacoffee.com/joelgmsec)
