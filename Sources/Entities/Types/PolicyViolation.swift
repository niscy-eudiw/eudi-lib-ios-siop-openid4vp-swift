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

/// A single policy rule violation, produced by a `RegistrationCertificatePolicy`.
///
/// Whether a violation halts processing or is a warning is determined by how it
/// is returned inside `Authorization`, not by the violation itself.
public struct PolicyViolation: Sendable, Equatable {
  public let violation: String

  public init(_ violation: String) {
    precondition(!violation.isEmpty, "violation must not be empty")
    self.violation = violation
  }
}

/// The outcome of a `RegistrationCertificatePolicy` evaluation.
public enum Authorization: Sendable, Equatable {
  /// Authorization succeeded. `warnings` are surfaced to the caller via the
  /// resolved `AuthorizationRequest`.
  case granted(warnings: [String: [PolicyViolation]] = [:])

  /// Authorization was denied. The resolver fails the request with an
  /// authorization-policy error carrying `error`.
  case notGranted(error: PolicyViolation)
}
