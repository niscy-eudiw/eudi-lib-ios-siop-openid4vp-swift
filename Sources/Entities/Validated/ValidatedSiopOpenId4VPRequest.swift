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
import PresentationExchange
import JOSESwift
import X509
import SwiftyJSON

// Enum defining the types of validated SIOP OpenID4VP requests
public enum ValidatedSiopOpenId4VPRequest {
  case idToken(request: IdTokenRequest)
  case vpToken(request: VpTokenRequest)
  case idAndVpToken(request: IdAndVpTokenRequest)
  
  public var transactionData: [String]? {
    switch self {
    case .idToken:
      return nil
    case .vpToken(let request):
      return request.transactionData
    case .idAndVpToken(let request):
      return request.transactionData
    }
  }
  
  public var responseMode: ResponseMode? {
    switch self {
    case .idToken(let request):
      request.responseMode
    case .vpToken(let request):
      request.responseMode
    case .idAndVpToken(let request):
      request.responseMode
    }
  }
  
  public var nonce: String? {
    switch self {
    case .idToken(let request):
      request.nonce
    case .vpToken(let request):
      request.nonce
    case .idAndVpToken(let request):
      request.nonce
    }
  }
  
  public var state: String? {
    switch self {
    case .idToken(let request):
      request.state
    case .vpToken(let request):
      request.state
    case .idAndVpToken(let request):
      request.state
    }
  }
  
  public var clientId: VerifierId {
    switch self {
    case .idToken(let request):
      request.client.id
    case .vpToken(let request):
      request.client.id
    case .idAndVpToken(let request):
      request.client.id
    }
  }
  
  public func clientMetaData() async -> ClientMetaData.Validated? {
    let source = switch self {
    case .idToken(let request):
      request.clientMetaDataSource
    case .vpToken(let request):
      request.clientMetaDataSource
    case .idAndVpToken(let request):
      request.clientMetaDataSource
    }
    
    switch source {
    case .passByValue(let metadata):
      return try? await ClientMetaDataValidator().validate(
        clientMetaData: metadata
      )
    case .none:
      return nil
    }
  }
}

// Extension for ValidatedSiopOpenId4VPRequest
public extension ValidatedSiopOpenId4VPRequest {
  
  static let WALLET_NONCE_FORM_PARAM = "wallet_nonce"
  static let WALLET_METADATA_FORM_PARAM = "wallet_metadata"
  
  // Initialize with a request URI
  init(
    requestUri: JWTURI,
    requestUriMethod: RequestUriMethod = .GET,
    clientId: String?,
    walletConfiguration: SiopOpenId4VPConfiguration? = nil
  ) async throws {
    
    guard let requestUrl = URL(string: requestUri) else {
      throw ValidationError.invalidRequestUri(requestUri)
    }
    
    let jwt = try await Self.getJWT(
      requestUriMethod: requestUriMethod,
      config: walletConfiguration,
      requestUrl: requestUrl,
      clientId: clientId
    )
    
    // Extract the payload from the JSON Web Token
    guard let payload = JSONWebToken(jsonWebToken: jwt)?.payload else {
      throw ValidationError.invalidAuthorizationData
    }
    
    // Extract the client ID and nonce from the payload
    guard let payloadcClientId = payload[Constants.CLIENT_ID].string else {
      throw ValidationError.missingRequiredField(".clientId")
    }
    
    guard let nonce = payload[Constants.NONCE].string else {
      throw ValidationError.missingRequiredField(".nonce")
    }
    
    let responseType = try ResponseType(authorizationRequestObject: payload)
    
    try await Self.verify(
      validator: AccessValidator(
        walletOpenId4VPConfig: walletConfiguration
      ),
      token: jwt,
      clientId: clientId
    )
    
    let client = try await Self.getClient(
      clientId: clientId,
      jwt: jwt,
      config: walletConfiguration
    )
    
    // Initialize the validated request based on the response type
    switch responseType {
    case .idToken:
      self = try ValidatedSiopOpenId4VPRequest.createIdToken(
        clientId: payloadcClientId,
        client: client,
        nonce: nonce,
        authorizationRequestObject: payload
      )
    case .vpToken:
      self = try ValidatedSiopOpenId4VPRequest.createVpToken(
        clientId: payloadcClientId,
        client: client,
        nonce: nonce,
        authorizationRequestObject: payload
      )
    case .vpAndIdToken:
      self = try ValidatedSiopOpenId4VPRequest.createIdVpToken(
        clientId: client.id.originalClientId,
        client: client,
        nonce: nonce,
        authorizationRequestObject: payload
      )
    case .code:
      throw ValidationError.unsupportedResponseType(".code")
    }
  }
  
  // Initialize with a JWT string
  init(
    request: JWTString,
    requestUriMethod: RequestUriMethod = .GET,
    walletConfiguration: SiopOpenId4VPConfiguration? = nil
  ) async throws {
    
    // Create a JSONWebToken from the JWT string
    let jsonWebToken = JSONWebToken(jsonWebToken: request)
    
    // Extract the payload from the JSON Web Token
    guard let payload = jsonWebToken?.payload else {
      throw ValidationError.invalidAuthorizationData
    }
    
    // Extract the client ID and nonce from the payload
    guard let clientId = payload[Constants.CLIENT_ID].string else {
      throw ValidationError.missingRequiredField(".clientId")
    }
    
    guard let nonce = payload[Constants.NONCE].string else {
      throw ValidationError.missingRequiredField(".nonce")
    }
    
    // Determine the response type from the payload
    let responseType = try ResponseType(authorizationRequestObject: payload)
    
    try await Self.verify(
      validator: AccessValidator(
        walletOpenId4VPConfig: walletConfiguration
      ),
      token: request,
      clientId: clientId
    )
    
    let client = try await Self.getClient(
      clientId: clientId,
      jwt: request,
      config: walletConfiguration
    )
    
    // Initialize the validated request based on the response type
    switch responseType {
    case .idToken:
      self = try ValidatedSiopOpenId4VPRequest.createIdToken(
        clientId: clientId,
        client: client,
        nonce: nonce,
        authorizationRequestObject: payload
      )
    case .vpToken:
      self = try ValidatedSiopOpenId4VPRequest.createVpToken(
        clientId: clientId,
        client: client,
        nonce: nonce,
        authorizationRequestObject: payload
      )
    case .vpAndIdToken:
      self = try ValidatedSiopOpenId4VPRequest.createIdVpToken(
        clientId: clientId,
        client: client,
        nonce: nonce,
        authorizationRequestObject: payload
      )
    case .code:
      throw ValidationError.unsupportedResponseType(".code")
    }
  }
  
  // Initialize with an AuthorisationRequestObject object
  init(
    authorizationRequestData: AuthorisationRequestObject,
    walletConfiguration: SiopOpenId4VPConfiguration? = nil
  ) async throws {
    let requesrUriMethod: RequestUriMethod = .init(
      method: authorizationRequestData.requestUriMethod
    )
    
    if let request = authorizationRequestData.request {
      try await self.init(
        request: request,
        requestUriMethod: requesrUriMethod,
        walletConfiguration: walletConfiguration
      )
      
    } else if let requestUrl = authorizationRequestData.requestUri {
      try await self.init(
        requestUri: requestUrl,
        requestUriMethod: requesrUriMethod,
        clientId: authorizationRequestData.clientId,
        walletConfiguration: walletConfiguration
      )
      
    } else {
      // Determine the response type from the authorization request data
      let responseType = try ResponseType(authorizationRequestData: authorizationRequestData)
      
      // Extract the nonce from the authorization request data
      guard let nonce = authorizationRequestData.nonce else {
        throw ValidationError.missingRequiredField(".nonce")
      }
      
      // Extract the client ID from the authorization request data
      guard let payloadcClientId = authorizationRequestData.clientId else {
        throw ValidationError.missingRequiredField(".clientId")
      }
      
      let client = try await Self.getClient(
        clientId: payloadcClientId,
        config: walletConfiguration
      )
      
      let jsonData = try JSONEncoder().encode(authorizationRequestData)
      let payload = try JSON(data: jsonData)
      
      // Initialize the validated request based on the response type
      switch responseType {
      case .idToken:
        self = try Self.createIdToken(
          clientId: payloadcClientId,
          client: client,
          nonce: nonce,
          authorizationRequestObject: payload
        )
      case .vpToken:
        self = try Self.createVpToken(
          clientId: payloadcClientId,
          client: client,
          nonce: nonce,
          authorizationRequestObject: payload
        )
      case .vpAndIdToken:
        self = try Self.createIdVpToken(
          clientId: payloadcClientId,
          client: client,
          nonce: nonce,
          authorizationRequestObject: payload
        )
      case .code:
        throw ValidationError.unsupportedResponseType(".code")
      }
    }
  }
  
  fileprivate static func getJWT(
    requestUriMethod: RequestUriMethod = .GET,
    config: SiopOpenId4VPConfiguration?,
    requestUrl: URL,
    clientId: String?
  ) async throws -> String {
    switch requestUriMethod {
    case .GET:
      return try await Self.getJwtString(
        fetcher: Fetcher(
          session: config?.session ?? URLSession.shared
        ),
        requestUrl: requestUrl
      )
    case .POST:
      guard let supportedMethods =
              config?.jarConfiguration.supportedRequestUriMethods else {
        throw AuthorizationError.invalidRequestUriMethod
      }
      
      guard let options = supportedMethods.isPostSupported() else {
        throw AuthorizationError.invalidRequestUriMethod
      }
      
      let nonce: String? = switch options.useWalletNonce {
      case .doNotUse:
        nil
      case .use(let byteLength):
        NonceGenerator.generate(length: byteLength)
      }
      
      let walletMetaData: JSON? = if options.includeWalletMetadata {
        if let config = config {
          walletMetaData(cfg: config)
        } else {
          nil
        }
      } else {
        nil
      }
      
      let jwt = try await Self.postJwtString(
        walletMetaData: walletMetaData,
        nonce: nonce,
        requestUrl: requestUrl
      )
      
      try config?.ensureValid(
        expectedClient: clientId,
        expectedWalletNonce: nonce,
        jwt: jwt
      )
      
      return jwt
    }
  }
  
  fileprivate struct ResultType: Codable {}
  fileprivate static func getJwtString(
    fetcher: Fetcher<ResultType> = Fetcher(),
    requestUrl: URL
  ) async throws -> String {
    let jwtResult = try await fetcher.fetchString(url: requestUrl)
    switch jwtResult {
    case .success(let string):
      return try Self.extractJWT(string)
    case .failure: throw ValidationError.invalidJwtPayload
    }
  }
  
  fileprivate static func postJwtString(
    poster: Poster = Poster(),
    walletMetaData: JSON?,
    nonce: String?,
    requestUrl: URL
  ) async throws -> String {
    
    // Building a combined JSON object
    var combined: [String: Any] = [:]
    if let walletMetaData = walletMetaData {
      combined[Self.WALLET_METADATA_FORM_PARAM] = walletMetaData.dictionaryObject
    }
    
    // Convert nonce to JSON and add to combined JSON
    if let nonce = nonce {
      combined[Self.WALLET_NONCE_FORM_PARAM] = nonce
    }
    
    let post = VerifierFormPost(
      additionalHeaders: ["Content-Type": ContentType.form.rawValue],
      url: requestUrl,
      formData: combined
    )
    
    let jwtResult: Result<String, PostError> = await poster.postString(
      request: post.urlRequest
    )
    switch jwtResult {
    case .success(let string):
      return try Self.extractJWT(string)
    case .failure: throw ValidationError.invalidJwtPayload
    }
  }
}

public extension ValidatedSiopOpenId4VPRequest {
  static func getClient(
    clientId: String?,
    jwt: JWTString,
    config: SiopOpenId4VPConfiguration?
  ) async throws -> Client {
    
    guard let clientId else {
      throw ValidationError.validationError("clientId is missing")
    }
    
    guard !clientId.isEmpty else {
      throw ValidationError.validationError("clientId is missing")
    }
    
    guard
      let verifierId = try? VerifierId.parse(clientId: clientId).get(),
      let scheme = config?.supportedClientIdSchemes.first(
        where: { $0.scheme.rawValue == verifierId.scheme.rawValue }
      ) ?? config?.supportedClientIdSchemes.first
    else {
      throw ValidationError.validationError("No supported client Id scheme")
    }
    
    switch scheme {
    case .preregistered(let clients):
      guard let client = clients[verifierId.originalClientId] else {
        throw ValidationError.validationError("preregistered client not found")
      }
      return .preRegistered(
        clientId: clientId,
        legalName: client.legalName
      )
      
    case .x509SanUri,
        .x509SanDns:
      guard let jws = try? JWS(compactSerialization: jwt) else {
        throw ValidationError.validationError("Unable to process JWT")
      }
      
      guard let chain: [String] = jws.header.x5c else {
        throw ValidationError.validationError("No certificate in header")
      }
      
      let certificates: [Certificate] = parseCertificates(from: chain)
      guard let certificate = certificates.first else {
        throw ValidationError.validationError("No certificate in chain")
      }
      
      return .x509SanUri(
        clientId: clientId,
        certificate: certificate
      )
      
    case .did(let keyLookup):
      return try await Self.didPublicKeyLookup(
        jws: try JWS(compactSerialization: jwt),
        clientId: clientId,
        keyLookup: keyLookup
      )
      
    case .verifierAttestation:
      return try Self.verifierAttestation(
        jwt: jwt,
        supportedScheme: scheme,
        clientId: clientId
      )
    case .redirectUri:
      guard let url = URL(string: verifierId.originalClientId) else {
        throw ValidationError.validationError("Client id must be uri for redirectUri scheme")
      }
      
      let configUrl = config?
        .supportedClientIdSchemes
        .first(where: { $0.scheme == scheme.scheme })?
        .redirectUri
      
      guard url == configUrl else {
        throw ValidationError.validationError("Client id must be uri for redirectUri scheme")
      }
      
      return .redirectUri(
        clientId: url
      )
    }
  }
  
  static func getClient(
    clientId: String,
    config: SiopOpenId4VPConfiguration?
  ) async throws -> Client {
    guard
      let verifierId = try? VerifierId.parse(clientId: clientId).get(),
      let scheme = config?.supportedClientIdSchemes.first(
        where: { $0.scheme.rawValue == verifierId.scheme.rawValue }
      ) ?? config?.supportedClientIdSchemes.first
    else {
      throw ValidationError.validationError("No supported client Id scheme")
    }
    
    switch scheme {
    case .preregistered(let clients):
      guard let client = clients[clientId] else {
        throw ValidationError.validationError("preregistered client nort found")
      }
      return .preRegistered(
        clientId: clientId,
        legalName: client.legalName
      )
    case .redirectUri:
      guard let url = URL(string: clientId) else {
        throw ValidationError.validationError("Client id must be uri for redirectUri scheme")
      }
      
      let configUrl = config?
        .supportedClientIdSchemes
        .first(where: { $0.scheme == scheme.scheme })?
        .redirectUri
      
      guard url == configUrl else {
        throw ValidationError.validationError("Client id must be uri for redirectUri scheme")
      }
      
      return .redirectUri(
        clientId: url
      )
    default:
      throw ValidationError.validationError("Scheme \(scheme) not supported")
    }
  }
}

// Private extension for ValidatedSiopOpenId4VPRequest
private extension ValidatedSiopOpenId4VPRequest {
  
  private static func verifierAttestation(
    jwt: JWTString,
    supportedScheme: SupportedClientIdScheme,
    clientId: String
  ) throws -> Client {
    guard case let .verifierAttestation(verifier, clockSkew) = supportedScheme else {
      throw ValidationError.validationError("Scheme should be verifier attestation")
    }
    
    guard let jws = try? JWS(compactSerialization: jwt) else {
      throw ValidationError.validationError("Unable to process JWT")
    }
    
    let expectedType = JOSEObjectType(rawValue: "verifier-attestation+jwt")
    guard jws.header.typ == expectedType?.rawValue else {
      throw ValidationError.validationError("verifier-attestation+jwt not found in JWT header")
    }
    
    _ = try jws.validate(using: verifier)
    let claims = try jws.verifierAttestationClaims()
    
    try TimeChecks(skew: clockSkew)
      .verify(
        claimsSet: .init(
          issuer: claims.iss,
          subject: claims.sub,
          audience: [],
          expirationTime: claims.exp,
          notBeforeTime: Date(),
          issueTime: claims.iat,
          jwtID: nil,
          claims: [:]
        )
      )
    return .attested(clientId: clientId)
  }
  
  private static func didPublicKeyLookup(
    jws: JWS,
    clientId: String,
    keyLookup: DIDPublicKeyLookupAgentType
  ) async throws -> Client {
    
    guard let kid = jws.header.kid else {
      throw ValidationError.validationError("kid not found in JWT header")
    }
    
    guard
      let keyUrl = AbsoluteDIDUrl.parse(kid),
      keyUrl.string.hasPrefix(clientId)
    else {
      throw ValidationError.validationError("kid not found in JWT header")
    }
    
    guard let clientIdAsDID = DID.parse(clientId) else {
      throw ValidationError.validationError("Invalid DID")
    }
    
    guard let publicKey = await keyLookup.resolveKey(from: clientIdAsDID) else {
      throw ValidationError.validationError("Unable to extract public key from DID")
    }
    
    try jws.verifyJWS(
      publicKey: publicKey
    )
    
    return .didClient(
      did: clientIdAsDID
    )
  }
  
  static func verify(
    validator: AccessValidating,
    token: JWTString,
    clientId: String?
  ) async throws {
    try? await validator.validate(clientId: clientId, jwt: token)
  }
  
  // Create a VP token request
  static func createVpToken(
    clientId: String,
    nonce: String,
    authorizationRequestData: AuthorisationRequestObject
  ) throws -> ValidatedSiopOpenId4VPRequest {
    let formats = try? VpFormats(
      jsonString: authorizationRequestData.clientMetaData
    )
    
    let querySource = try parseQuerySource(
      authorizationRequestData: authorizationRequestData
    )
    
    return .vpToken(request: .init(
      querySource: querySource,
      clientMetaDataSource: .init(authorizationRequestData: authorizationRequestData),
      clientId: clientId,
      client: .preRegistered(clientId: clientId, legalName: clientId),
      nonce: nonce,
      responseMode: try? .init(authorizationRequestData: authorizationRequestData),
      requestUriMethod: .init(method: authorizationRequestData.requestUriMethod),
      state: authorizationRequestData.state,
      vpFormats: try (formats ?? VpFormats.empty()),
      transactionData: authorizationRequestData.transactionData
    ))
  }
  
  // Create an ID token request
  static func createIdToken(
    clientId: String,
    client: Client,
    nonce: String,
    authorizationRequestObject: JSON
  ) throws -> ValidatedSiopOpenId4VPRequest {
    .idToken(request: .init(
      idTokenType: try .init(authorizationRequestObject: authorizationRequestObject),
      clientMetaDataSource: .init(authorizationRequestObject: authorizationRequestObject),
      clientId: clientId,
      client: client,
      nonce: nonce,
      scope: authorizationRequestObject[Constants.SCOPE].stringValue,
      responseMode: try? .init(authorizationRequestObject: authorizationRequestObject),
      state: authorizationRequestObject[Constants.STATE].string
    ))
  }
  
  // Create a VP token request
  static func createVpToken(
    clientId: String,
    client: Client,
    nonce: String,
    authorizationRequestObject: JSON
  ) throws -> ValidatedSiopOpenId4VPRequest {
    let formats = try? VpFormats(jsonString: authorizationRequestObject[Constants.CLIENT_METADATA].string)
    
    let querySource = try parseQuerySource(
      authorizationRequestObject: authorizationRequestObject
    )
    
    return .vpToken(request: .init(
      querySource: querySource,
      clientMetaDataSource: .init(authorizationRequestObject: authorizationRequestObject),
      clientId: clientId,
      client: client,
      nonce: nonce,
      responseMode: try? .init(authorizationRequestObject: authorizationRequestObject),
      requestUriMethod: .init(method: authorizationRequestObject[Constants.REQUEST_URI_METHOD].string),
      state: authorizationRequestObject[Constants.STATE].string,
      vpFormats: try (formats ?? VpFormats.default()),
      transactionData: authorizationRequestObject[Constants.TRANSACTION_DATA].array?.compactMap { $0.string }
    ))
  }
  
  // Create an ID and VP token request
  static func createIdVpToken(
    clientId: String,
    client: Client,
    nonce: String,
    authorizationRequestObject: JSON
  ) throws -> ValidatedSiopOpenId4VPRequest {
    let formats = try? VpFormats(jsonString: authorizationRequestObject[Constants.CLIENT_METADATA].string)
    
    let querySource = try parseQuerySource(
      authorizationRequestObject: authorizationRequestObject
    )
    
    return .idAndVpToken(request: .init(
      idTokenType: try .init(authorizationRequestObject: authorizationRequestObject),
      querySource: querySource,
      clientMetaDataSource: .init(authorizationRequestObject: authorizationRequestObject),
      clientId: clientId,
      client: client,
      nonce: nonce,
      scope: authorizationRequestObject[Constants.SCOPE].stringValue,
      responseMode: try? .init(authorizationRequestObject: authorizationRequestObject),
      state: authorizationRequestObject[Constants.STATE].string,
      vpFormats: try (formats ?? VpFormats.default()),
      transactionData: authorizationRequestObject[Constants.TRANSACTION_DATA].array?.compactMap { $0.string }
    ))
  }
  
  private static func parseQuerySource(authorizationRequestData: AuthorisationRequestObject) throws -> QuerySource {
    let hasPd = authorizationRequestData.presentationDefinition != nil
    let hasPdUri = authorizationRequestData.presentationDefinitionUri != nil
    // let hasScope = authorizationRequestObject[Constants.SCOPE].string != nil
    let hasDcqlQuery = authorizationRequestData.dcqlQuery != nil
    
    let querySourceCount = [hasPd, hasPdUri, hasDcqlQuery].filter { $0 }.count
    
    if querySourceCount > 1 {
      throw ValidationError.multipleQuerySources
    }
    
    if hasPd || hasPdUri {
      return .byPresentationDefinitionSource(
        try .init(authorizationRequestData: authorizationRequestData)
      )
    } else if hasDcqlQuery {
      guard let json = authorizationRequestData.dcqlQuery else {
        throw ValidationError.invalidQuerySource
      }
      return .dcqlQuery(try .init(from: json))
      
    } else {
      throw ValidationError.invalidQuerySource
    }
  }
  
  private static func parseQuerySource(authorizationRequestObject: JSON) throws -> QuerySource {
    
    let object = JSON(authorizationRequestObject.dictionaryValue.filter { $0.value != JSON.null })
    let hasPd = object[Constants.PRESENTATION_DEFINITION].exists()
    let hasPdUri = object[Constants.PRESENTATION_DEFINITION_URI].exists()
    let hasDcqlQuery = object[Constants.DCQL_QUERY].exists()
    
    let querySourceCount = [hasPd, hasPdUri, hasDcqlQuery].filter { $0 }.count
    
    if querySourceCount > 1 {
      throw ValidationError.multipleQuerySources
    }
    
    if hasPd || hasPdUri {
      return .byPresentationDefinitionSource(
        try .init(authorizationRequestObject: authorizationRequestObject)
      )
    } else if hasDcqlQuery {
      return .dcqlQuery(try .init(from: authorizationRequestObject[Constants.DCQL_QUERY]))
      
    } else {
      throw ValidationError.invalidQuerySource
    }
  }
  
  /// Extracts the JWT token from a given JSON string or JWT string.
  /// - Parameter string: The input string containing either a JSON object with a JWT field or a JWT string.
  /// - Returns: The extracted JWT token.
  /// - Throws: An error of type `ValidatedAuthorizationError` if the input string is not a valid JSON or JWT, or if there's a decoding error.
  private static func extractJWT(_ string: String) throws -> String {
    if string.isValidJSONString {
      if let jsonData = string.data(using: .utf8) {
        do {
          let decodedObject = try JSONDecoder().decode(RemoteJWT.self, from: jsonData)
          return decodedObject.jwt
        } catch {
          throw error
        }
      } else {
        throw ValidationError.invalidJwtPayload
      }
    } else {
      if string.isValidJWT() {
        return string
      } else {
        throw ValidationError.invalidJwtPayload
      }
    }
  }
}

// Protocol to verify JWT claims
private protocol JWTClaimsSetVerifier {
  func verify(claimsSet: JWTClaimsSet) throws
}

private enum JWTVerificationError: Error {
  case expiredJWT
  case issuedInFuture
  case issuedAfterExpiration
  case notYetActive
  case activeAfterExpiration
  case activeBeforeIssuance
}

private struct DateUtils {
  static func isAfter(_ date1: Date, _ date2: Date, _ skew: TimeInterval) -> Bool {
    return date1.timeIntervalSince(date2) > skew
  }
  
  static func isBefore(_ date1: Date, _ date2: Date, _ skew: TimeInterval = .zero) -> Bool {
    return date1.timeIntervalSince(date2) < -skew
  }
}

// TimeChecks class implementation in Swift
private class TimeChecks: JWTClaimsSetVerifier {
  private let skew: TimeInterval
  
  init(skew: TimeInterval) {
    self.skew = skew
  }
  
  func verify(claimsSet: JWTClaimsSet) throws {
    let now = Date()
    let skewInSeconds = skew
    
    if let exp = claimsSet.expirationTime {
      if !DateUtils.isAfter(exp, now, skewInSeconds) {
        throw JWTVerificationError.expiredJWT
      }
    }
    
    if let iat = claimsSet.issueTime {
      if !DateUtils.isBefore(iat, now) {
        throw JWTVerificationError.issuedInFuture
      }
      
      if let exp = claimsSet.expirationTime, !iat.timeIntervalSince(exp).isLess(than: 0) {
        throw JWTVerificationError.issuedAfterExpiration
      }
    }
  }
}

private extension SiopOpenId4VPConfiguration {
  
  func ensureValid(
    expectedClient: String?,
    expectedWalletNonce: String?,
    jwt: JWTString
  ) throws {
    
    let jws = try JWS(compactSerialization: jwt)
    
    guard let expectedClient = expectedClient else {
      throw ValidationError.validationError("expectedClient should not be nil")
    }
    
    guard let jwsClientID = getValueForKey(
      from: jwt,
      key: "client_id"
    ) as? String else {
      throw ValidationError.validationError("client_id should not be nil")
    }
    
    let id = try? VerifierId.parse(clientId: jwsClientID).get()
    let expectedId = try? VerifierId.parse(clientId: expectedClient).get()
    guard id?.originalClientId == expectedId?.originalClientId else {
      throw ValidationError.validationError("client_id's do not match")
    }
    
    if expectedWalletNonce != nil {
      guard let jwsNonce = getValueForKey(
        from: jwt,
        key: ValidatedSiopOpenId4VPRequest.WALLET_NONCE_FORM_PARAM
      ) as? String else {
        throw ValidationError.validationError("nonce should not be nil")
      }
      
      guard jwsNonce == expectedWalletNonce else {
        throw ValidationError.validationError("nonce's do not match")
      }
    }
    
    guard let algorithm = jws.header.algorithm else {
      throw ValidationError.validationError("algorithm should not be nil")
    }
    
    guard jarConfiguration.supportedAlgorithms.contains(where: { $0.name == algorithm.rawValue }) else {
      throw ValidationError.validationError("nonce's do not match")
    }
  }
  
  func getValueForKey(from jwtString: String, key: String) -> Any? {
    do {
      let jwt = try JWS(compactSerialization: jwtString)
      let payloadData = jwt.payload.data()
      
      let jsonObject = try JSONSerialization.jsonObject(with: payloadData, options: [])
      guard let payloadDict = jsonObject as? [String: Any] else {
        return nil
      }
      return payloadDict[key]
      
    } catch {
      return nil
    }
  }
}
