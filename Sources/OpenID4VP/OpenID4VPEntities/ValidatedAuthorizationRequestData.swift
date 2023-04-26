import Foundation

public struct ValidatedAuthorizationRequestData {
  let responseType: ResponseType
  let presentationDefinitionSource: PresentationDefinitionSource?
  let clientMetaDataSource: ClientMetaDataSource?
  let clientIdScheme: ClientIdScheme?
  let nonce: Nonce
  let scope: Scope?
  let responseMode: ResponseMode

  // TODO: The responseType is responsible for assesing which validated structure we map to
  public init(
    responseType: ResponseType,
    presentationDefinitionSource: PresentationDefinitionSource?,
    clientMetaDataSource: ClientMetaDataSource?,
    clientIdScheme: ClientIdScheme?,
    nonce: Nonce,
    scope: Scope?,
    responseMode: ResponseMode) {
    self.responseType = responseType
    self.presentationDefinitionSource = presentationDefinitionSource
    self.clientMetaDataSource = clientMetaDataSource
    self.clientIdScheme = clientIdScheme
    self.nonce = nonce
    self.scope = scope
    self.responseMode = responseMode
  }
}

extension ValidatedAuthorizationRequestData {
  init(authorizationRequestData: AuthorizationRequestData?) throws {
    guard
      let authorizationRequestData = authorizationRequestData
    else {
      throw ValidatedAuthorizationError.noAuthorizationData
    }

    self.init(
      responseType: try .init(authorizationRequestData: authorizationRequestData),
      presentationDefinitionSource: try .init(authorizationRequestData: authorizationRequestData),
      clientMetaDataSource: .init(authorizationRequestData: authorizationRequestData),
      clientIdScheme: try .init(authorizationRequestData: authorizationRequestData),
      nonce: "",
      scope: "",
      responseMode: .none
    )
  }
}