import SwiftUI

struct ContentView: View {
    private let info = AppInfo.current

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "key.fill")
                .font(.system(size: 56))
                .foregroundColor(.accentColor)
            Text("PhoneKey")
                .font(.largeTitle.bold())
            Text("\(info.versionDescription) · iOS \(UIDevice.current.systemVersion)")
                .font(.footnote.monospacedDigit())
                .foregroundColor(.secondary)
            Label("Not connected", systemImage: "xmark.circle")
                .foregroundColor(.secondary)
                .padding(.top, 24)
        }
        .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
