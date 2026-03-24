
import CryptoTokenKit

enum RemoteHSMTokenIDs {
    /// Igual a `com.apple.ctk.class-id` no Info.plist da extensão.
    static let driverClassID: TKTokenDriver.ClassID = "com.example.RemoteHSMTokenDemo.RemoteHSMToken"
    /// Tem de ser o mesmo valor passado em `addTokenConfiguration(for:)` na app host.
    static let defaultInstanceID: TKToken.InstanceID = "remote-hsm-default"
}