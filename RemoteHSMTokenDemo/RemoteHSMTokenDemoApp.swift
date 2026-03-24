//
//  RemoteHSMTokenDemoApp.swift
//  RemoteHSMTokenDemo
//
//  Created by Victor Yuji Maehira on 23/03/26.
//

import SwiftUI

@main
struct RemoteHSMTokenDemoApp: App {
    init() {
        RemoteHSMTokenRegistration.registerDefaultToken()
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
