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
import CryptoKit

import XCTest
import JOSESwift

@testable import SiopOpenID4VP

final class DirectPostTests: DiXCTest {

  func testValidDirectPostAuthorisationResponseGivenValidResolutionAndConsent() async throws {

    let validator = ClientMetaDataValidator()
    let metaData = try await validator.validate(clientMetaData: Constants.testClientMetaData())

    // Obtain an id token resolution
    let resolved: ResolvedRequestData = .idToken(
      request: .init(
        idTokenType: .attesterSigned,
        presentationQuery: .byPresentationDefinition(.init(
          id: "dummy-id",
          inputDescriptors: [])),
        clientMetaData: metaData,
        client: Constants.testClient,
        nonce: TestsConstants.testNonce,
        responseMode: TestsConstants.testResponseMode,
        state: TestsConstants.generateRandomBase64String(),
        scope: TestsConstants.testScope,
        jarmRequirement: .noRequirement
      )
    )

    // Generate a random JWT
    let jwt = TestsConstants.generateRandomJWT()

    // Obtain consent
    let consent: ClientConsent = .idToken(idToken: jwt)

    // Generate a direct post authorisation response
    let response = try? AuthorizationResponse(
      resolvedRequest: resolved,
      consent: consent,
      walletOpenId4VPConfig: nil
    )

    XCTAssertNotNil(response)
  }

  func testExpectedErrorGivenValidResolutionAndNegaticeConsent() async throws {

    let validator = ClientMetaDataValidator()
    let metaData = try await validator.validate(clientMetaData: Constants.testClientMetaData())

    // Obtain an id token resolution
    let resolved: ResolvedRequestData = .idToken(
      request: .init(
        idTokenType: .attesterSigned,
        presentationQuery: .byPresentationDefinition(.init(
          id: "dummy-id",
          inputDescriptors: [])),
        clientMetaData: metaData,
        client: Constants.testClient,
        nonce: TestsConstants.testNonce,
        responseMode: TestsConstants.testResponseMode,
        state: TestsConstants.generateRandomBase64String(),
        scope: TestsConstants.testScope,
        jarmRequirement: .noRequirement
      )
    )

    // Do not obtain consent
    let consent: ClientConsent = .negative(message: "user_cancelled")

    do {
      // Generate an error since consent was not given
      let response = try AuthorizationResponse(
        resolvedRequest: resolved,
        consent: consent,
        walletOpenId4VPConfig: nil
      )

      switch response {
      case .directPost(_, data: let data):
        switch data {
        case .noConsensusResponseData(state: let state, error: _):
          XCTAssert(true, state)
          return
        default: XCTAssert(false, "Incorrect response type")
        }
      default: XCTAssert(false, "Incorrect response type")
      }
    } catch ValidationError.negativeConsent {
      XCTAssert(true)
      return
    } catch {
      print(error.localizedDescription)
      XCTAssert(false)
    }

    XCTAssert(false)
  }

  func testSDKEndtoEndDirectPostVpTokenWithEncryption() async throws {

    let publicKeysURL = URL(string: "\(TestsConstants.host)/wallet/public-keys.json")!

    let rsaPrivateKey = try KeyController.generateRSAPrivateKey()
    let rsaPublicKey = try KeyController.generateRSAPublicKey(from: rsaPrivateKey)
    let privateKey = try KeyController.generateECDHPrivateKey()

    let rsaJWK = try RSAPublicKey(
      publicKey: rsaPublicKey,
      additionalParameters: [
        "use": "sig",
        "kid": UUID().uuidString,
        "alg": "RS256"
      ])

    let keySet = try WebKeySet(jwk: rsaJWK)

    let wallet: SiopOpenId4VPConfiguration = .init(
      subjectSyntaxTypesSupported: [
        .decentralizedIdentifier,
        .jwkThumbprint
      ],
      preferredSubjectSyntaxType: .jwkThumbprint,
      decentralizedIdentifier: try .init(rawValue: "did:example:123"),
      signingKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [
        .preregistered(clients: [
          TestsConstants.testClientId: .init(
            clientId: TestsConstants.testClientId,
            legalName: "Verifier",
            jarSigningAlg: .init(.RS256),
            jwkSetSource: .fetchByReference(url: publicKeysURL)
          )
        ])
      ],
      vpFormatsSupported: [],
      jarConfiguration: .encryptionOption,
      vpConfiguration: VPConfiguration.default(),
      jarmConfiguration: .default()
    )

    let sdk = SiopOpenID4VP(walletConfiguration: wallet)
    /// To get this URL, visit https://dev.verifier.eudiw.dev/
    /// and  "Request for the entire PID"
    /// Copy the "Authenticate with wallet link", choose the value for "request_uri"
    /// Decode the URL online and paste it below in the url variable
    /// Note:  The url is only valid for one use
    let url = "#06"

    overrideDependencies()
    let result = await sdk.authorize(
      url: URL(
        string: url
      )!
    )

    switch result {
    case .jwt(request: let request):
      let presentationDefinition = try?  XCTUnwrap(
        request.presentationDefinition,
        "Unable to resolve presentation definition"
      )

      XCTAssertNotNil(presentationDefinition)

      // Obtain consent
      let submission = TestsConstants.presentationSubmission(presentationDefinition!)
      let verifiablePresentations: [VerifiablePresentation] = [
        .generic(TestsConstants.cbor)
      ]
      let consent: ClientConsent = .vpToken(
        vpContent: .presentationExchange(
          verifiablePresentations: verifiablePresentations,
          presentationSubmission: submission
        )
      )

      // Generate a direct post authorisation response
      let response = try? XCTUnwrap(AuthorizationResponse(
        resolvedRequest: request,
        consent: consent,
        walletOpenId4VPConfig: wallet
      ), "Expected a non-nil item")

      // Dispatch
      XCTAssertNotNil(response)

      let result: DispatchOutcome = try await sdk.dispatch(response: response!)
      switch result {
      case .accepted:
        XCTAssert(true)
      default:
        XCTAssert(false)
      }
    default:
      XCTExpectFailure()
      XCTAssert(false)
    }
  }

  func testSDKEndtoEndDirectPostVpTokenWithNoEncryption() async throws {

    let publicKeysURL = URL(string: "\(TestsConstants.host)/wallet/public-keys.json")!

    let rsaPrivateKey = try KeyController.generateRSAPrivateKey()
    let rsaPublicKey = try KeyController.generateRSAPublicKey(from: rsaPrivateKey)
    let privateKey = try KeyController.generateECDHPrivateKey()

    let rsaJWK = try RSAPublicKey(
      publicKey: rsaPublicKey,
      additionalParameters: [
        "use": "sig",
        "kid": UUID().uuidString,
        "alg": "RS256"
      ])

    let keySet = try WebKeySet(jwk: rsaJWK)

    let wallet: SiopOpenId4VPConfiguration = .init(
      subjectSyntaxTypesSupported: [
        .decentralizedIdentifier,
        .jwkThumbprint
      ],
      preferredSubjectSyntaxType: .jwkThumbprint,
      decentralizedIdentifier: try .init(rawValue: "did:example:123"),
      signingKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [
        .preregistered(clients: [
          TestsConstants.testClientId: .init(
            clientId: TestsConstants.testClientId,
            legalName: "Verifier",
            jarSigningAlg: .init(.RS256),
            jwkSetSource: .fetchByReference(url: publicKeysURL)
          )
        ]),
        .x509SanDns(trust: { _ in
          return true
        })
      ],
      vpFormatsSupported: [],
      jarConfiguration: .encryptionOption,
      vpConfiguration: VPConfiguration.default(),
      jarmConfiguration: .default()
    )

    let sdk = SiopOpenID4VP(walletConfiguration: wallet)
    /// To get this URL, visit https://dev.verifier.eudiw.dev/
    /// and  "Request for the entire PID"
    /// Copy the "Authenticate with wallet link", choose the value for "request_uri"
    /// Decode the URL online and paste it below in the url variable
    /// Note:  The url is only valid for one use
    let url = "#11"

    overrideDependencies()
    let result = await sdk.authorize(
      url: URL(
        string: url
      )!
    )

    switch result {
    case .jwt(request: let request):
      let presentationDefinition = try?  XCTUnwrap(
        request.presentationDefinition,
        "Unable to resolve presentation definition"
      )

      XCTAssertNotNil(presentationDefinition)

      // Obtain consent
      let consent: ClientConsent = .vpToken(
        vpContent: .presentationExchange(
          verifiablePresentations: [
            .generic(TestsConstants.cbor)
          ],
          presentationSubmission: TestsConstants.presentationSubmission(presentationDefinition!)
        )
      )

      // Generate a direct post authorisation response
      let response = try? XCTUnwrap(AuthorizationResponse(
        resolvedRequest: request,
        consent: consent,
        walletOpenId4VPConfig: wallet
      ), "Expected a non-nil item")

      // Dispatch
      XCTAssertNotNil(response)

      let result: DispatchOutcome = try await sdk.dispatch(response: response!)
      switch result {
      case .accepted:
        XCTAssert(true)
      default:
        XCTAssert(false)
      }
    default:
      XCTExpectFailure()
      XCTAssert(false)
    }
  }
}
