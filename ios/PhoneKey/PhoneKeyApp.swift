import os
import SwiftUI
import UIKit

// UIKit app and scene delegates instead of a SwiftUI `App`: on iOS 15 the
// controller behind a SwiftUI `WindowGroup` keeps UIKit's iPhone default and
// never turns upside down, whatever Info.plist says. A desk station often
// stands with the cable on top, so the root controller here allows both
// portrait directions.

@main
@MainActor
final class AppDelegate: UIResponder, UIApplicationDelegate {
    /// One model for the life of the app, even if iOS reconnects the scene.
    let model: AppModel
    private let log = Logger(subsystem: "net.geraldhofbauer.phonekey", category: "app")

    override init() {
        model = AppModel()
        super.init()
    }

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        NotificationCenter.default.addObserver(self, selector: #selector(sceneWillConnect(_:)),
                                               name: UIScene.willConnectNotification, object: nil)
        return true
    }

    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: nil, sessionRole: connectingSceneSession.role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }

    /// iOS restores the scene session saved by an older build, and with it
    /// that build's scene delegate. Builds with a SwiftUI `App` saved SwiftUI's
    /// delegate, which shows nothing now, so such a scene is taken over here.
    /// A URL that cold-launches such a scene is lost; once the app is swiped
    /// away in the app switcher, iOS starts a fresh session with `SceneDelegate`.
    @objc private func sceneWillConnect(_ notification: Notification) {
        guard let scene = notification.object as? UIWindowScene, !(scene.delegate is SceneDelegate) else { return }
        log.info("Taking over a restored scene from an older build")
        let delegate = SceneDelegate()
        scene.delegate = delegate
        delegate.attach(to: scene)
    }
}

@MainActor
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var model: AppModel? { (UIApplication.shared.delegate as? AppDelegate)?.model }

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession,
               options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        attach(to: windowScene)
        // A pairing URL that launched the app.
        if let url = connectionOptions.urlContexts.first?.url { model?.open(url) }
    }

    /// Puts the app's window on the scene, once.
    func attach(to windowScene: UIWindowScene) {
        guard window == nil, let model else { return }
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = StationHostingController(rootView: ContentView().environmentObject(model))
        self.window = window
        window.makeKeyAndVisible()
    }

    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        if let url = URLContexts.first?.url { model?.open(url) }
    }

    func sceneDidBecomeActive(_ scene: UIScene) { model?.scenePhaseChanged(.active) }
    func sceneWillResignActive(_ scene: UIScene) { model?.scenePhaseChanged(.inactive) }
    func sceneDidEnterBackground(_ scene: UIScene) { model?.scenePhaseChanged(.background) }
}

/// Portrait either way up. The iPhone 7 has a home button, so iOS allows
/// upside down there; Info.plist lists both directions.
final class StationHostingController<Content: View>: UIHostingController<Content> {
    override var supportedInterfaceOrientations: UIInterfaceOrientationMask {
        [.portrait, .portraitUpsideDown]
    }
}
