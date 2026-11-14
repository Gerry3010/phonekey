import SwiftUI

@main
struct PhoneKeyApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onOpenURL { model.open($0) }
        }
        .onChange(of: scenePhase) { model.scenePhaseChanged($0) }
    }
}
