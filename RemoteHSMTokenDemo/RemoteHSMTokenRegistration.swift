import CryptoTokenKit

enum RemoteHSMTokenRegistration {
    /// Mesmos literais que `RemoteHSMToken/RemoteHSMTokenIDs.swift`.
    private static let driverClassID: TKTokenDriver.ClassID = "com.example.RemoteHSMTokenDemo.RemoteHSMToken"
    private static let defaultInstanceID: TKToken.InstanceID = "remote-hsm-default"
    static func registerDefaultToken() {
        guard let driverConfig = TKTokenDriver.Configuration.driverConfigurations[driverClassID] else {
            return
        }
        _ = driverConfig.addTokenConfiguration(for: defaultInstanceID)
    }
}