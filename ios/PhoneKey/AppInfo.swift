import Foundation

/// Version metadata read from a bundle's Info.plist.
struct AppInfo: Equatable {
    let version: String
    let build: String

    static var current: AppInfo { AppInfo(bundle: .main) }

    init(bundle: Bundle) {
        version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
    }

    var versionDescription: String { "v\(version) (\(build))" }
}
