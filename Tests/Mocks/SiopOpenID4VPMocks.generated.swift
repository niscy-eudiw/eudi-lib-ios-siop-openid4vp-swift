//
//  SiopOpenID4VPMocks.generated.swift
//  SiopOpenID4VP
//
//  Generated by Mockingbird v0.20.0.
//  DO NOT EDIT
//

// swiftlint:disable all

@_exported import PresentationExchange
@testable import Mockingbird
@testable import SiopOpenID4VP
import Combine
import CryptoKit
import Foundation
import JOSESwift
import PresentationExchange
import Security
import Swift
import X509
import os

private let mkbGenericStaticMockContext = Mockingbird.GenericStaticMockContext()

// MARK: - Mocked AuthorisationServiceType
public final class AuthorisationServiceTypeMock: AuthorisationServiceType, Mockingbird.Mock {
  typealias MockingbirdSupertype = AuthorisationServiceType
  public static let mockingbirdContext = Mockingbird.Context()
  public let mockingbirdContext = Mockingbird.Context(["generator_version": "0.20.0", "module_name": "SiopOpenID4VP"])

  fileprivate init(sourceLocation: Mockingbird.SourceLocation) {
    self.mockingbirdContext.sourceLocation = sourceLocation
    AuthorisationServiceTypeMock.mockingbirdContext.sourceLocation = sourceLocation
  }

  // MARK: Mocked `formCheck`(`poster`: Posting, `response`: AuthorizationResponse)
  public func `formCheck`(`poster`: Posting, `response`: AuthorizationResponse) async throws -> (String, Bool) {
    return try await self.mockingbirdContext.mocking.didInvoke(Mockingbird.SwiftInvocation(selectorName: "`formCheck`(`poster`: Posting, `response`: AuthorizationResponse) async throws -> (String, Bool)", selectorType: Mockingbird.SelectorType.method, arguments: [Mockingbird.ArgumentMatcher(`poster`), Mockingbird.ArgumentMatcher(`response`)], returnType: Swift.ObjectIdentifier(((String, Bool)).self))) {
      self.mockingbirdContext.recordInvocation($0)
      let mkbImpl = self.mockingbirdContext.stubbing.implementation(for: $0)
      if let mkbImpl = mkbImpl as? (Posting, AuthorizationResponse) async throws -> (String, Bool) { return try await mkbImpl(`poster`, `response`) }
      if let mkbImpl = mkbImpl as? () async throws -> (String, Bool) { return try await mkbImpl() }
      for mkbTargetBox in self.mockingbirdContext.proxy.targets(for: $0) {
        switch mkbTargetBox.target {
        case .super:
          break
        case .object(let mkbObject):
          guard var mkbObject = mkbObject as? MockingbirdSupertype else { break }
          let mkbValue: (String, Bool) = try await mkbObject.`formCheck`(poster: `poster`, response: `response`)
          self.mockingbirdContext.proxy.updateTarget(&mkbObject, in: mkbTargetBox)
          return mkbValue
        }
      }
      if let mkbValue = self.mockingbirdContext.stubbing.defaultValueProvider.value.provideValue(for: ((String, Bool)).self) { return mkbValue }
      self.mockingbirdContext.stubbing.failTest(for: $0, at: self.mockingbirdContext.sourceLocation)
    }
  }

  public func `formCheck`(`poster`: @autoclosure () -> Posting, `response`: @autoclosure () -> AuthorizationResponse) async -> Mockingbird.Mockable<Mockingbird.ThrowingAsyncFunctionDeclaration, (Posting, AuthorizationResponse) async throws -> (String, Bool), (String, Bool)> {
    return Mockingbird.Mockable<Mockingbird.ThrowingAsyncFunctionDeclaration, (Posting, AuthorizationResponse) async throws -> (String, Bool), (String, Bool)>(context: self.mockingbirdContext, invocation: Mockingbird.SwiftInvocation(selectorName: "`formCheck`(`poster`: Posting, `response`: AuthorizationResponse) async throws -> (String, Bool)", selectorType: Mockingbird.SelectorType.method, arguments: [Mockingbird.resolve(`poster`), Mockingbird.resolve(`response`)], returnType: Swift.ObjectIdentifier(((String, Bool)).self)))
  }

  // MARK: Mocked `formPost`<T: Codable>(`poster`: Posting, `response`: AuthorizationResponse)
  public func `formPost`<T: Codable>(`poster`: Posting, `response`: AuthorizationResponse) async throws -> T {
    return try await self.mockingbirdContext.mocking.didInvoke(Mockingbird.SwiftInvocation(selectorName: "`formPost`<T: Codable>(`poster`: Posting, `response`: AuthorizationResponse) async throws -> T", selectorType: Mockingbird.SelectorType.method, arguments: [Mockingbird.ArgumentMatcher(`poster`), Mockingbird.ArgumentMatcher(`response`)], returnType: Swift.ObjectIdentifier((T).self))) {
      self.mockingbirdContext.recordInvocation($0)
      let mkbImpl = self.mockingbirdContext.stubbing.implementation(for: $0)
      if let mkbImpl = mkbImpl as? (Posting, AuthorizationResponse) async throws -> T { return try await mkbImpl(`poster`, `response`) }
      if let mkbImpl = mkbImpl as? () async throws -> T { return try await mkbImpl() }
      for mkbTargetBox in self.mockingbirdContext.proxy.targets(for: $0) {
        switch mkbTargetBox.target {
        case .super:
          break
        case .object(let mkbObject):
          guard var mkbObject = mkbObject as? MockingbirdSupertype else { break }
          let mkbValue: T = try await mkbObject.`formPost`(poster: `poster`, response: `response`)
          self.mockingbirdContext.proxy.updateTarget(&mkbObject, in: mkbTargetBox)
          return mkbValue
        }
      }
      if let mkbValue = self.mockingbirdContext.stubbing.defaultValueProvider.value.provideValue(for: (T).self) { return mkbValue }
      self.mockingbirdContext.stubbing.failTest(for: $0, at: self.mockingbirdContext.sourceLocation)
    }
  }

  public func `formPost`<T: Codable>(`poster`: @autoclosure () -> Posting, `response`: @autoclosure () -> AuthorizationResponse) async -> Mockingbird.Mockable<Mockingbird.ThrowingAsyncFunctionDeclaration, (Posting, AuthorizationResponse) async throws -> T, T> {
    return Mockingbird.Mockable<Mockingbird.ThrowingAsyncFunctionDeclaration, (Posting, AuthorizationResponse) async throws -> T, T>(context: self.mockingbirdContext, invocation: Mockingbird.SwiftInvocation(selectorName: "`formPost`<T: Codable>(`poster`: Posting, `response`: AuthorizationResponse) async throws -> T", selectorType: Mockingbird.SelectorType.method, arguments: [Mockingbird.resolve(`poster`), Mockingbird.resolve(`response`)], returnType: Swift.ObjectIdentifier((T).self)))
  }
}

/// Returns a concrete mock of `AuthorisationServiceType`.
public func mock(_ type: AuthorisationServiceType.Protocol, file: StaticString = #file, line: UInt = #line) -> AuthorisationServiceTypeMock {
  return AuthorisationServiceTypeMock(sourceLocation: Mockingbird.SourceLocation(file, line))
}
