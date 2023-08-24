/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import Foundation
import XCTest
import JOSESwift

@testable import SiopOpenID4VP

final class ECDHTests: DiXCTest {

  var controller: JOSEController!
  var privateKey: SecKey!
  var publicKey: SecKey!
  
  override func tearDown() {
    super.tearDown()
  }
  
  override func setUp() {
    controller = JOSEController()
    privateKey = try! controller.generateECDHPrivateKey()
    publicKey = try! controller.generateECDHPublicKey(from: privateKey!)
  }
  
  func testEncryptionThenDecryption() async throws {
    
    let privateJWK = try ECPrivateKey(privateKey: privateKey)
    let publicJWK = try ECPublicKey(publicKey: publicKey)
    
    let convertedPublicKey: SecKey = try! publicJWK.converted(to: SecKey.self)
    XCTAssert(publicKey == convertedPublicKey)
    
    let header = JWEHeader(
      keyManagementAlgorithm: .ECDH_ES,
      contentEncryptionAlgorithm: .A128CBCHS256
    )

    let encryptionPayload = try Payload([
      "message": "Babis is the best"
    ].toThrowingJSONData())
    
    let encrypter = Encrypter(
      keyManagementAlgorithm: .ECDH_ES,
      contentEncryptionAlgorithm: .A128CBCHS256,
      encryptionKey: publicJWK
    )!
    
    let jwe = try JWE(
      header: header,
      payload: encryptionPayload,
      encrypter: encrypter
    )

    XCTAssert(jwe.compactSerializedString.replacingOccurrences(of: "..", with: ".").isValidJWT())
  
    let encryptedJwe = try JWE(compactSerialization: jwe.compactSerializedString)
    
    let decrypter = Decrypter(
      keyManagementAlgorithm: .ECDH_ES,
      contentEncryptionAlgorithm: .A128CBCHS256,
      decryptionKey: privateJWK
    )!
    
    let decryptionPayload = try encryptedJwe.decrypt(using: decrypter)
    let dictionary = try JSONSerialization.jsonObject(with: decryptionPayload.data(), options: []) as? [String: Any]
    
    XCTAssert(dictionary!["message"] as! String == "Babis is the best")
  }
}
