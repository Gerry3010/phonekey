# PhoneKey — Notizen für Claude

Ein altes iPhone 7 als Peripherie-Station für einen Linux-Rechner: FIDO2-Security-Key mit
Touch ID, Kamera, Mikrofon, Freigabe-Knopf für Coding-Agents. Monorepo aus iOS-App,
Linux-Daemon und gemeinsamem Protokoll.

## Die eine Regel

Das Zielgerät ist ein **iPhone 7 mit höchstens iOS 15.8**, das Deployment Target bleibt `15.0`.

- Nur iOS-15-APIs: kein `NavigationStack`, keine Observation (`@Observable`), keine Passkey- oder
  Credential-Provider-APIs, kein Swift Charts. Previews als `PreviewProvider`.
- **Es gibt keinen iOS-15-Simulator mehr** (die Runtime läuft auf macOS 26 nicht). Simulator-Tests
  laufen auf iOS 17+. Ob etwas auf iOS 15 funktioniert, zeigt nur das echte Gerät.
- Die App läuft **nur im Vordergrund** (Desk-Station mit Guided Access). Im Hintergrund stoppt die
  Kamera, Sockets brechen ab und Touch ID fragt nicht. Nichts bauen, das Hintergrundbetrieb braucht.

## Arbeitsteilung

- `ios/` ist die Apple-Seite.
- `linux/` ist der Daemon in Go. Er zielt auf Linux, läuft aber auch auf macOS und wird dort über
  den usbmuxd des Macs gegen das echte iPhone getestet. Claude auf dem Mac darf hier ausdrücklich
  mitbauen, damit Claude auf Linux frei bleibt. Linux-only-Teile (`/dev/uhid` ab Phase 3) hinter
  Build-Tags, getestet in einer Linux-VM.
- `docs/protocol.md` ist der Vertrag zwischen beiden, `docs/protocol-vectors.json` die
  Testvektoren dazu. Änderungen nur per PR. Der Code folgt der Spec, nicht umgekehrt.
- Swift (CryptoKit) und Go (`flynn/noise`) implementieren Noise unabhängig voneinander. Das ist
  gewollt: Interop-Tests zwischen beiden fangen Fehler, die eine einzelne Implementierung nicht sieht.

## Sicherheit

- Private Schlüssel entstehen im Secure Enclave und verlassen ihn nie.
- Keine Keys, Pairing-Secrets, Challenges oder Credential-IDs in Logs. `os_log`/`Logger` für so
  etwas nur mit `privacy: .private`.
- Das Repo ist **public**: keine Secrets, Test-Credentials, Gerätenamen oder lokalen Pfade committen.

## Git

- Nie direkt auf `main`. Branches `feat/…`, `fix/…`, `chore/…`, `docs/…` von `staging` abzweigen,
  PRs gegen `staging`.
- Commits mit der GitHub-Noreply-Adresse (lokal per `git config user.email` gesetzt).
- Keine Worktrees.

## Aufbau

```
ios/PhoneKey.xcodeproj   Xcode-16+-Format mit synchronisierten Ordnern
ios/PhoneKey/            App-Code: neue Dateien landen automatisch im Target
ios/PhoneKey-Info.plist  nur das URL-Schema phonekey://, Rest kommt aus INFOPLIST_KEY_*
ios/PhoneKeyCore/        Swift-Package: Noise, Wire, PhoneSession (plattformneutral, testbar)
ios/PhoneKeyTests/       XCTest-Unit-Tests, gehostet in der App
docs/architecture.md     Desk-Station, Transport, Grenzen, Roadmap
docs/protocol.md         Wire-Protokoll (Entwurf)
linux/                   Linux-Daemon
```

Neue Swift-Dateien brauchen keinen Eintrag im `project.pbxproj`. Das pbxproj nur für Build Settings
oder neue Targets anfassen.

## Build & Test

```bash
(cd ios/PhoneKeyCore && swift test)      # Noise, Wire, Session – auf dem Mac, in Sekunden
(cd linux && go vet ./... && go test ./...)
xcodebuild -project ios/PhoneKey.xcodeproj -scheme PhoneKey -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
xcodebuild test -project ios/PhoneKey.xcodeproj -scheme PhoneKey -destination 'platform=iOS Simulator,name=iPhone SE (3rd generation)'
```

Das iPhone SE (3. Gen.) hat dieselbe Bildschirmgröße wie das iPhone 7 (4,7″).

**Interop-Test ohne iPhone:** Der Simulator teilt sich das Loopback-Interface mit dem Mac. App im
Simulator starten, dann `phonekey pair -connect tcp:127.0.0.1:20555` und die ausgegebene URL mit
`xcrun simctl openurl booted '<url>'` öffnen. `PHONEKEY_CONFIG_DIR` auf ein Testverzeichnis setzen,
damit echte Host-Keys unberührt bleiben. Im Simulator liefert die Kamera ein Testbild.

**Vektoren:** Nach jeder Protokolländerung `go run ./cmd/gen-vectors ../docs/protocol-vectors.json`
in `linux/`. Go und Swift prüfen beide gegen diese Datei.
