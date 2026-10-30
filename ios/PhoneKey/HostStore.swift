import Foundation
import os
import PhoneKeyCore

struct PairedHost: Codable, Identifiable, Equatable {
    var key: Data
    var name: String
    var pairedAt: Date

    var id: Data { key }
}

/// Paired computers and the pending pairing. Sessions call the HostRegistry
/// methods from background tasks, the UI reads the published copies.
final class HostStore: ObservableObject, HostRegistry {
    struct Pending: Equatable {
        let invite: PairingInvite
        let expires: Date
    }

    static let pairingWindow: TimeInterval = 5 * 60

    @Published private(set) var hosts: [PairedHost] = []
    @Published private(set) var pending: Pending?
    /// The most recent pairing, for the success screen.
    @Published private(set) var lastPaired: PairedHost?

    private let lock = NSLock()
    private var storedHosts: [PairedHost] = []
    private var storedPending: Pending?
    private let log = Logger(subsystem: "net.geraldhofbauer.phonekey", category: "hosts")

    init() {
        do {
            if let data = try Keychain.read("hosts") {
                storedHosts = try JSONDecoder().decode([PairedHost].self, from: data)
            }
        } catch {
            log.error("Could not load paired hosts: \(String(describing: error), privacy: .public)")
        }
        hosts = storedHosts
    }

    // MARK: HostRegistry (any thread)

    func isPaired(hostKey: Data) -> Bool {
        locked { storedHosts.contains { $0.key == hostKey } }
    }

    func pendingInvite() -> PairingInvite? {
        locked {
            guard let p = storedPending, p.expires > Date() else { return nil }
            return p.invite
        }
    }

    func completePairing(_ invite: PairingInvite) {
        let host = PairedHost(key: invite.hostKey, name: invite.hostName, pairedAt: Date())
        locked {
            storedHosts.removeAll { $0.key == host.key }
            storedHosts.append(host)
            storedPending = nil
        }
        persist()
        publish(lastPaired: host)
    }

    // MARK: UI

    func confirm(_ invite: PairingInvite) {
        locked { storedPending = Pending(invite: invite, expires: Date().addingTimeInterval(Self.pairingWindow)) }
        publish()
    }

    func cancelPending() {
        locked { storedPending = nil }
        publish()
    }

    func remove(_ host: PairedHost) {
        locked { storedHosts.removeAll { $0.key == host.key } }
        persist()
        publish()
    }

    func name(for key: Data) -> String? {
        locked { storedHosts.first { $0.key == key }?.name }
    }

    // MARK: Internals

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    private func persist() {
        let snapshot = locked { storedHosts }
        do {
            try Keychain.write(try JSONEncoder().encode(snapshot), "hosts")
        } catch {
            log.error("Could not save paired hosts: \(String(describing: error), privacy: .public)")
        }
    }

    private func publish(lastPaired newlyPaired: PairedHost? = nil) {
        let (hosts, pending) = locked { (storedHosts, storedPending) }
        DispatchQueue.main.async {
            self.hosts = hosts
            self.pending = pending
            if let newlyPaired { self.lastPaired = newlyPaired }
        }
    }
}
