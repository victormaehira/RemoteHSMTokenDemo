//
//  TokenDriver.swift
//  RemoteHSMToken
//
//  Created by Victor Yuji Maehira on 23/03/26.
//

import CryptoTokenKit

final class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {
    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        try Token(tokenDriver: self, instanceID: configuration.instanceID)
    }
}