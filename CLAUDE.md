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

- `ios/` ist die Apple-Seite (Claude auf dem Mac).
- `linux/` ist der Linux-Daemon (Claude auf Linux).
- `docs/protocol.md` ist der Vertrag zwischen beiden. Änderungen nur per PR, und die andere Seite
  erfährt davon. Der Code folgt der Spec, nicht umgekehrt.

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
ios/PhoneKeyTests/       XCTest-Unit-Tests, gehostet in der App
docs/architecture.md     Desk-Station, Transport, Grenzen, Roadmap
docs/protocol.md         Wire-Protokoll (Entwurf)
linux/                   Linux-Daemon
```

Neue Swift-Dateien brauchen keinen Eintrag im `project.pbxproj`. Das pbxproj nur für Build Settings
oder neue Targets anfassen.

## Build & Test

```bash
xcodebuild -project ios/PhoneKey.xcodeproj -scheme PhoneKey -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
xcodebuild test -project ios/PhoneKey.xcodeproj -scheme PhoneKey -destination 'platform=iOS Simulator,name=iPhone SE (3rd generation)'
```

Das iPhone SE (3. Gen.) hat dieselbe Bildschirmgröße wie das iPhone 7 (4,7″).
