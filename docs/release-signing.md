# Release packaging and signing

GreyNOC Slop Detection supports release packaging for Windows, macOS, and Linux through Electron Builder, plus an optional Inno Setup installer for Windows.

## Important signing reality

Installers can be generated automatically, but trusted code signing requires real certificates issued to GreyNOC or the release publisher.

Do not commit private keys, `.pfx` files, Apple certificates, API keys, or notarization credentials to this repository.

## Windows

### Outputs

Run:

```powershell
npm run release:win
```

This builds:

- NSIS installer
- portable executable
- unpacked Windows app in `release/win-unpacked`

Optional Inno Setup installer:

```powershell
npm run release:win:inno
```

This builds an installer from:

```text
installer/windows/greynoc-slop-detection.iss
```

and outputs it to:

```text
release/inno
```

### Windows signing

Local Windows builds are unsigned by default unless signing credentials are supplied in the environment. This keeps installer packaging reproducible on developer machines without requiring certificate-store access, and the release script skips Electron Builder's executable signing/editing step for unsigned builds.

To reduce Windows SmartScreen and antivirus warnings, use a real Authenticode code signing certificate.

Best results come from an Extended Validation code signing certificate, because it usually builds SmartScreen reputation faster than standard OV certificates. A certificate does not guarantee zero warnings on day one; reputation still matters.

For Electron Builder, set signing variables in your release environment, for example:

```powershell
$env:CSC_LINK="C:\secure\GreyNOC-CodeSigning.pfx"
$env:CSC_KEY_PASSWORD="your-private-password"
npm run release:win
```

For Inno Setup, configure `signtool.exe` and pass a SignTool command through your build environment. Example pattern:

```powershell
$env:GN_SIGNTOOL='signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f C:\secure\GreyNOC-CodeSigning.pfx /p YOUR_PASSWORD $f'
npm run release:win:inno
```

Keep certificate passwords in CI secrets or a local secure vault.

## macOS

### Outputs

Run on macOS:

```bash
npm run release:mac
```

This builds:

- DMG
- ZIP

### macOS signing and notarization

For a professional macOS release, enroll in the Apple Developer Program and use a Developer ID Application certificate.

Typical environment variables for Electron Builder:

```bash
export CSC_LINK=/secure/GreyNOC-DeveloperID.p12
export CSC_KEY_PASSWORD='your-private-password'
export APPLE_ID='developer-account@example.com'
export APPLE_APP_SPECIFIC_PASSWORD='app-specific-password'
export APPLE_TEAM_ID='TEAMID1234'
npm run release:mac
```

macOS Gatekeeper expects Developer ID signing and notarization for apps distributed outside the Mac App Store.

## Linux

### Outputs

Run on Linux:

```bash
npm run release:linux
```

This builds:

- AppImage
- DEB
- tar.gz

Linux desktop releases are usually not Authenticode-style signed like Windows. For a more professional Linux distribution path, publish checksums and optionally GPG-sign release artifacts:

```bash
sha256sum release/* > release/SHA256SUMS.txt
gpg --detach-sign --armor release/SHA256SUMS.txt
```

For apt repositories, sign the repository metadata with GPG.

## Recommended release matrix

Build each platform on its native OS:

| Platform | Build host | Primary output | Signing path |
| --- | --- | --- | --- |
| Windows | Windows 10/11 | NSIS or Inno installer | Authenticode certificate |
| macOS | macOS | DMG and ZIP | Developer ID + notarization |
| Linux | Linux | AppImage, DEB, tar.gz | SHA256 + optional GPG |

## Local commands

```powershell
# Windows NSIS and portable
npm run release:win

# Windows Inno Setup installer
npm run release:win:inno
```

```bash
# macOS
npm run release:mac

# Linux
npm run release:linux
```
