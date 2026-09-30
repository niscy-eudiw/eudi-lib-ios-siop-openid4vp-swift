import Foundation
import XCTest
import SwiftyJSON
import JOSESwift
@testable import OpenID4VP

final class TransactionDataValidationTests: XCTestCase {
  private func query(holderBinding: Bool = true) throws -> PresentationQuery {
    .byDigitalCredentialsQuery(try .init(credentials: [
      .init(id: .init(value: "pid"), format: .init(format: "dc+sd-jwt"), meta: ["vct_values": ["pid"]], requireCryptographicHolderBinding: holderBinding)
    ]))
  }

  func testRejectsInvalidEnvelopesWithTransactionErrorCode() throws {
    let valid: [String: Any] = ["type": "example", "credential_ids": ["pid"]]
    let supported = try SupportedTransactionDataType(type: .init(value: "example"))
    var invalid: [[String: Any]] = []
    for (key, value): (String, Any) in [("type", "unknown"), ("credential_ids", []), ("credential_ids", ["unknown"]), ("credential_ids", [1]),
                                       ("transaction_data_hashes_alg", []), ("transaction_data_hashes_alg", "sha-256"),
                                       ("transaction_data_hashes_alg", ["unknown"]), ("transaction_data_hashes_alg", NSNull())] {
      var object = valid; object[key] = value; invalid.append(object)
    }
    let values = try invalid.map { try JSONSerialization.data(withJSONObject: $0).base64URLEncodedString() } + ["%%%", "bnVsbA", "W10"]
    for value in values {
      XCTAssertThrowsError(try TransactionData.parse(value, supportedTypes: [supported], presentationQuery: query()).get()) { error in
        guard let error = error as? ValidationError else { XCTFail("Expected typed error"); return }
        XCTAssertEqual(AuthorizationRequestErrorCode.fromError(error), .invalidTransactionData)
      }
    }
    let encoded = try JSONSerialization.data(withJSONObject: valid).base64URLEncodedString()
    XCTAssertNoThrow(try TransactionData.parse(encoded, supportedTypes: [supported], presentationQuery: query()).get())
    XCTAssertThrowsError(try TransactionData.parse(encoded, supportedTypes: [supported], presentationQuery: query(holderBinding: false)).get())
  }

  func testMalformedArraysAreRetainedUntilAuthentication() throws {
    for raw in ["null", "{}", "42", "[1]", "[\"valid\",1]", "bad JSON"] {
      var components = URLComponents(string: "openid4vp://authorize")!
      components.queryItems = [.init(name: "client_id", value: "redirect_uri:https://example.org/response"), .init(name: "transaction_data", value: raw)]
      guard case .plain(let request) = try UnvalidatedRequest.make(from: components.string!).get() else { XCTFail(); return }
      XCTAssertTrue(request.malformedTransactionData, raw)
    }
    let payload = Data(#"{"transaction_data":["valid",1]}"#.utf8).base64URLEncodedString()
    XCTAssertTrue(try XCTUnwrap(JWTDecoder.decodeJWT("header.\(payload).signature")).malformedTransactionData)
    let decoded = try JSONDecoder().decode(UnvalidatedRequestObject.self, from: Data(#"{"transaction_data":null}"#.utf8))
    XCTAssertTrue(decoded.malformedTransactionData)
  }

  func testResolutionAndDispatchPreserveInvalidTransactionData() async throws {
    let capture = TransactionErrorCapture()
    let networking = TransactionErrorNetworking(capture: capture)
    let config = try OpenId4VPConfiguration(privateKey: KeyController.generateRSAPrivateKey(), publicWebKeySet: .init(keys: []),
                                           supportedClientIdSchemes: [.redirectUri], vpConfiguration: .init(vpFormatsSupported: .default(), supportedTransactionDataTypes: []),
                                           session: networking, responseEncryptionConfiguration: .unsupported)
    let sdk = OpenID4VP(walletConfiguration: config)
    for raw in ["[]", "{}", "[1]", "[\"bad-base64\"]"] {
      var url = URLComponents(string: "openid4vp://authorize")!
      url.queryItems = [
        .init(name: "client_id", value: "redirect_uri:https://example.org/response"),
        .init(name: "response_uri", value: "https://example.org/response"),
        .init(name: "response_type", value: "vp_token"), .init(name: "response_mode", value: "direct_post"),
        .init(name: "nonce", value: "nonce"), .init(name: "state", value: "state + &"),
        .init(name: "dcql_query", value: #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["pid"]}}]}"#),
        .init(name: "transaction_data", value: raw)
      ]
      let result = await sdk.authorize(fetcher: Fetcher<String>(session: networking), poster: Poster(session: networking), url: url.url!)
      guard case .invalidResolution(let error, let details) = result else { XCTFail("Expected invalid resolution for \(raw)"); continue }
      XCTAssertEqual(AuthorizationRequestErrorCode.fromError(error), .invalidTransactionData)
      XCTAssertNotNil(details)
      _ = try await sdk.dispatch(error: error, details: details)
      let body = await capture.lastBody
      XCTAssertTrue(body.contains("error=invalid_transaction_data"), body)
      XCTAssertTrue(body.contains("state=state+%2B+%26"), body)
      XCTAssertFalse(body.contains("vp_token="))
    }
  }

  func testNegativeConsentWithoutState() throws {
    let request = ResolvedRequestData(request: .init(presentationQuery: try query(), clientMetaData: nil,
      client: .redirectUri(clientId: "https://example.org/response"), nonce: "nonce",
      responseMode: .directPost(responseURI: URL(string: "https://example.org/response")!), state: nil,
      vpFormatsSupported: try .default(), responseEncryptionSpecification: nil))
    let response = try AuthorizationResponse(resolvedRequest: request, consent: .negative(message: "access_denied"))
    guard case .directPost(_, let payload) = response else { XCTFail(); return }
    XCTAssertEqual(try JSON(data: JSONEncoder().encode(payload))["error"].string, "access_denied")
  }

  func testEncryptedErrorResponsePreservesCodeAndState() async throws {
    let key = try KeyController.generateECDHPrivateKey()
    let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
    let jwk = try ECPublicKey(publicKey: publicKey, additionalParameters: ["use": "enc", "kid": "test", "alg": "ECDH-ES"])
    let spec = ResponseEncryptionSpecification(responseEncryptionAlg: .init(.ECDH_ES), responseEncryptionEnc: .init(.A128GCM), clientKey: try .init(jwks: [jwk]))
    let capture = TransactionErrorCapture()
    let poster = Poster(session: TransactionErrorNetworking(capture: capture))
    let dispatcher = ErrorDispatcher(error: ValidationError.invalidTransactionData("Invalid QES"),
      details: .init(responseMode: .directPostJWT(responseURI: URL(string: "https://example.org/response")!),
                     nonce: "nonce", state: "state", clientId: nil, responseEncryptionSpecification: spec))
    _ = try await dispatcher.dispatch(poster: poster)
    let body = await capture.lastBody
    let fields = URLComponents(string: "https://example.org/?" + body)?.queryItems
    let encoded = try XCTUnwrap(fields?.first(where: { $0.name == "response" })?.value)
    XCTAssertFalse(body.contains("error="))
    let encrypted = try JWE(compactSerialization: encoded)
    let decrypter = try XCTUnwrap(Decrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A128GCM, decryptionKey: try ECPrivateKey(privateKey: key)))
    let json = try JSON(data: encrypted.decrypt(using: decrypter).data())
    XCTAssertEqual(json["error"].string, "invalid_transaction_data")
    XCTAssertEqual(json["state"].string, "state")
  }

  func testAllSpecifiedErrorCodesEncode() throws {
    let examples: [(ValidationError, String)] = [(.invalidScope, "invalid_scope"), (.invalidRequest, "invalid_request"),
      (.invalidClientMetadata, "invalid_client"), (.negativeConsent, "access_denied"), (.invalidFormat, "vp_formats_not_supported"),
      (.invalidRequestUriMethod, "invalid_request_uri_method"), (.invalidTransactionData("bad"), "invalid_transaction_data"), (.walletUnavailable, "wallet_unavailable")]
    for (error, expected) in examples {
      let payload = AuthorizationResponsePayload.invalidRequest(error: error, nonce: "nonce", state: nil, clientId: nil)
      let json = try JSON(data: JSONEncoder().encode(payload))
      XCTAssertEqual(json["error"].string, expected)
      XCTAssertNil(json["state"].string)
    }
  }
}

private actor TransactionErrorCapture {
  var lastBody = ""
  func record(_ request: URLRequest) { lastBody = String(decoding: request.httpBody ?? Data(), as: UTF8.self) }
}

private struct TransactionErrorNetworking: Networking {
  let capture: TransactionErrorCapture
  func data(from url: URL) async throws -> (Data, URLResponse) { throw URLError(.unsupportedURL) }
  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    await capture.record(request)
    return (Data("{}".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
  }
}
