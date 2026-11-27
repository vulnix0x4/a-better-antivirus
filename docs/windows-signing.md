# Code-signing the Windows programs

ABA's Windows programs (`aba_<version>_windows_amd64.exe`, `..._arm64.exe`, the `aba.exe` in each zip,
`ABA-Setup.exe` and the two `aba.exe` files inside it) can be code-signed with Microsoft's
**Artifact Signing** service (it used to be called Trusted Signing). A signature tells Windows who made the file
and that nobody changed it since. Windows Defender and SmartScreen trust signed files sooner, and Windows shows a
real publisher name instead of "Unknown publisher".

Until the steps below are done, releases are built exactly as before, unsigned. Nothing breaks either way.

- [Part 1: what the owner does (sign-up)](#part-1-sign-up-owner)
- [Part 2: what the maintainer does with the values](#part-2-turn-it-on-maintainer)
- [How it works](#how-it-works)

## Part 1: sign-up (owner)

**What it costs:** about **$10 a month** (the "Basic" plan, 5,000 signatures a month; a release uses about 7). Billing
starts the day the signing account is created and isn't pro-rated. A credit card is needed. Free and trial Azure
accounts can't use this service: it has to be "pay-as-you-go".

**Who can do it:** as an individual (not a company), you must live in the **United States or Canada** and have a
government photo ID (passport, driver's license or ID card) and a phone with the **Microsoft Authenticator** app.

> [!IMPORTANT]
> The signature carries **your legal name**, exactly as on your ID. Everyone who installs ABA can see it: Windows
> shows it as the publisher when ABA-Setup.exe asks for permission, and in the file's properties. That is how
> individual signing works; there's no way to show a project name instead. If you don't want your name on it,
> stop here and tell me.

Set aside about an hour, and expect to wait anywhere from **a day to about six weeks** (Microsoft says 1 to 30
business days) for Microsoft to check your ID in step 4.

### 1. Create the Azure account

1. Go to <https://azure.microsoft.com/pricing/purchase-options/pay-as-you-go> and click **Start with pay-as-you-go**
   (not "Try Azure for free").
2. Sign in with a Microsoft account, or create one. Use an email address you'll keep: Microsoft sends the ID-check
   results and renewal notices there.
3. Fill in the sign-up form:
   - If it asks whether the account is for an **individual or a company**, choose **Individual**.
   - Your **name and address must be exactly as on your ID** (same spelling, same middle name or initial, same
     address). The ID check in step 4 compares them, and a mismatch is the most common reason it fails.
   - Add your card and finish.
4. You land on the Azure portal, <https://portal.azure.com>. Everything below happens there.

### 2. Create the signing account

1. In the search box at the top of the portal, type **Artifact Signing** and open **Artifact Signing Accounts**.
   (If it isn't found, search for **Trusted Signing Accounts**: same thing, old name.)
2. Click **+ Create** and fill in:
   - **Subscription:** your pay-as-you-go subscription (usually the only one).
   - **Resource group:** click **Create new** and type `aba-signing`.
   - **Account name:** something like `abasigning` followed by a few digits, e.g. `abasigning2611`. Letters and
     digits only, 3 to 24 characters, starting with a letter. It must be unique across all of Azure: if it's taken,
     add other digits. **Write it down.**
   - **Region:** **East US**.
   - **Pricing tier:** **Basic**.
3. Click **Review + create**, then **Create**. Wait for "Your deployment is complete" and click **Go to resource**.

If Azure says the subscription is "not registered" for `Microsoft.CodeSigning`: search for **Subscriptions**, open
yours, choose **Resource providers** on the left, search `Microsoft.CodeSigning`, select it, click **Register**,
wait a minute, then try step 2 again.

### 3. Give yourself permission to verify your identity

Azure doesn't let even the account owner start the ID check without this.

1. On the signing account's page, click **Access control (IAM)** on the left.
2. Click **+ Add** → **Add role assignment**.
3. In the search box, type **Identity Verifier** and pick **Artifact Signing Identity Verifier** (or **Trusted Signing
   Identity Verifier**). Click **Next**.
4. Leave "User, group, or service principal" selected, click **+ Select members**, pick yourself, click **Select**.
5. Click **Review + assign** twice.

### 4. Verify your identity

1. On the signing account's page, open **Identity validations** on the left (it may be under **Objects**).
2. Click **+ New identity** → **Public**.
3. Choose **Individual**. Azure fills in your name and address from the account you created in step 1: check they
   match your ID. Click **Create**.
4. Follow the link it gives you to verify with your ID. It walks you through the **Microsoft Authenticator** app:
   you take a photo of your ID and a selfie (a partner company, AU10TIX, checks them for Microsoft).
5. Back in the portal, the identity validation shows **In progress**. Microsoft emails you when it's done. Wait
   until its status is **Completed**. If it says **Action required**, open it and do what it asks.

### 5. Create the certificate profile

Only after step 4 shows **Completed**.

1. On the signing account's page, open **Certificate profiles** (may be under **Objects**) → **+ Create** →
   **Public Trust**.
2. **Name:** `abapublic` (letters and digits only). **Write it down.**
3. **Identity validation:** pick the one from step 4 (it shows your name). Leave the rest as it is.
4. Click **Create**.

### 6. Let ABA's GitHub release robot use it

This lets the release robot on GitHub sign files, without any password being stored on GitHub: Azure only accepts
requests that GitHub vouches come from ABA's release job.

1. At the top of the portal, click the **Cloud Shell** icon (it looks like `>_`). Choose **Bash**. If it asks about
   storage, choose **No storage account required**, pick your subscription and click **Apply**.
2. In the first line below, replace `abasigning2611` with **your account name from step 2**. Then copy the whole
   block, paste it into the Cloud Shell window and press Enter.

```bash
ACCOUNT=abasigning2611
RG=aba-signing
SCOPE=$(az resource show -g "$RG" -n "$ACCOUNT" --resource-type Microsoft.CodeSigning/codeSigningAccounts --query id -o tsv)
APP=$(az ad app create --display-name "ABA GitHub release signing" --query appId -o tsv)
SP=$(az ad sp create --id "$APP" --query id -o tsv)
az ad app federated-credential create --id "$APP" --parameters '{"name":"github-aba-release","issuer":"https://token.actions.githubusercontent.com","subject":"repo:vulnix0x4@187458047/a-better-antivirus@1460857444:environment:release","audiences":["api://AzureADTokenExchange"]}' >/dev/null
sleep 30
az role assignment create --assignee-object-id "$SP" --assignee-principal-type ServicePrincipal --scope "$SCOPE" --role "Artifact Signing Certificate Profile Signer" >/dev/null \
  || az role assignment create --assignee-object-id "$SP" --assignee-principal-type ServicePrincipal --scope "$SCOPE" --role "Trusted Signing Certificate Profile Signer" >/dev/null
echo
echo "---- send everything below to Claude ----"
echo "AZURE_CLIENT_ID=$APP"
echo "AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)"
echo "ARTIFACT_SIGNING_ACCOUNT=$ACCOUNT"
echo "ARTIFACT_SIGNING_ENDPOINT=$(az resource show --ids "$SCOPE" --query properties.accountUri -o tsv)"
```

3. It takes about a minute and ends with four lines under "send everything below to Claude". If you see red error
   text instead, send me a screenshot of the whole window.

### 7. Send these to Claude

| Value | Where it comes from | Secret? |
|---|---|---|
| `AZURE_CLIENT_ID` | the Cloud Shell output (step 6) | No |
| `AZURE_TENANT_ID` | the Cloud Shell output | No |
| `ARTIFACT_SIGNING_ACCOUNT` | the Cloud Shell output (your account name from step 2) | No |
| `ARTIFACT_SIGNING_ENDPOINT` | the Cloud Shell output (looks like `https://eus.codesigning.azure.net/`) | No |
| `ARTIFACT_SIGNING_PROFILE` | your certificate profile name from step 5 (`abapublic`) | No |

None of these is a password. They are names and ID numbers: on their own they don't let anyone sign anything,
because Azure only accepts signing requests from ABA's release job on GitHub.

**Never send** (to me or anyone): your Microsoft/Azure password, sign-in codes, recovery codes, card details, or
photos of your ID.

**Later:** Microsoft may email you to renew your identity validation from time to time. When that happens, do what
the email asks (it's like step 4 again), or signing stops working until you do.

To stop paying: delete the signing account (portal → the account → **Delete**). Files already signed stay signed.

## Part 2: turn it on (maintainer)

1. Put the five values from Part 1, step 7, in the repository's **release** environment as **variables** (not
   secrets: they're identifiers, and the workflows' `if:` checks need to read them):

   ```sh
   for kv in AZURE_CLIENT_ID=... AZURE_TENANT_ID=... ARTIFACT_SIGNING_ACCOUNT=... \
             ARTIFACT_SIGNING_ENDPOINT=... ARTIFACT_SIGNING_PROFILE=...; do
     gh variable set "${kv%%=*}" --env release --body "${kv#*=}" --repo vulnix0x4/a-better-antivirus
   done
   ```

2. Run **Actions → Windows signing (dry run) → Run workflow** on `main`. It builds everything a release does,
   signs it, checks every signature (`installer/verify.ps1 -Signed`) and keeps the files as the run's artifact.
   Nothing is published. Download `ABA-Setup.exe` from it and look at **Properties → Digital Signatures** on a
   Windows PC.
3. Once it's green, the next `vX.Y.Z` tag is signed. After the first signed release ships, update the lines that
   say releases aren't code-signed: `README.md` (Installer section), and the SmartScreen step in `site/index.html`
   (the "UNSIGNED-INSTALLER BLOCK"). The release notes' footer in `.goreleaser.yaml` switches by itself.

## How it works

- `scripts/setup-windows-signing.ps1` (release job, only when the `release` environment has
  `ARTIFACT_SIGNING_ACCOUNT`) fetches pinned, SHA-256-checked copies of `signtool.exe`
  (`Microsoft.Windows.SDK.BuildTools`) and the Artifact Signing client (`Microsoft.ArtifactSigning.Client`), writes
  the client's `metadata.json`, and sets `ABA_WINDOWS_SIGNING` for the GoReleaser step. Sign-in is `azure/login`
  with GitHub's OIDC token and a federated credential for `repo:vulnix0x4@187458047/a-better-antivirus@1460857444:environment:release`:
  no client secret exists anywhere. That subject is GitHub's immutable form, which names the owner and repository
  by their numeric IDs as well (`gh api repos/vulnix0x4/a-better-antivirus/actions/oidc/customization/sub` shows
  it). A credential made for the plain `repo:vulnix0x4/a-better-antivirus:...` form fails with AADSTS700213.
- GoReleaser runs `installer/build` after each `aba.exe` is built. With `ABA_WINDOWS_SIGNING` set, it signs that
  `aba.exe` in place (`scripts/sign-windows.ps1`), then copies it into the installer, and signs `ABA-Setup.exe`
  after Inno Setup compiles it. All of that happens before GoReleaser makes the zips and `SHA256SUMS.txt`, so the
  checksums (and their ed25519 signature, which the auto-updater checks) are of the signed files, and the
  `aba.exe` inside `ABA-Setup.exe` is still byte for byte the published one.
- Every signature is SHA-256 and timestamped by `http://timestamp.acs.microsoft.com`. Artifact Signing
  certificates last only three days; the timestamp keeps the signature valid long after.
- `sign-windows.ps1` checks each file right after signing (`signtool verify /pa` and `Get-AuthenticodeSignature`,
  with a timestamp), so a bad signature fails the build before anything is published. `installer/verify.ps1
  -Signed` checks all seven programs again on the finished `dist\`.
- On every pull request, the Installer workflow's **Code-signed build** job runs the same steps with a throwaway
  certificate trusted only on that runner (`-Mode test`), and installs and uninstalls ABA with the signed
  `ABA-Setup.exe`.
- `install.ps1` isn't signed: it's run as `irm ... | iex`, which never checks a script signature, and it's served
  straight from `main`, so a signature would have to be committed and redone on every edit. It already checks the
  release's ed25519 signature and hashes before it runs anything.
