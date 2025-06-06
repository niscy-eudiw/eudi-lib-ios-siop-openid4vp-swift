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
import SwiftyJSON

public struct VerifierAttestations {
  public let value: [Attestation]
  
  public init(value: [Attestation]) {
    precondition(!value.isEmpty, "Verifier attestations must not be empty")
    self.value = value
  }
  
  public func filterOrNull(predicate: (Attestation) -> Bool) -> VerifierAttestations? {
    let matches = value.filter(predicate)
    return matches.isEmpty ? nil : VerifierAttestations(value: matches)
  }
  
  public var description: String {
    return String(describing: value)
  }
  
  public struct Attestation {
    public let format: String
    public let data: JSON
    public let queryIds: [String]?
    
    public init(format: String, data: JSON, queryIds: [String]? = nil) {
      self.format = format
      self.data = data
      self.queryIds = queryIds
    }
    
    public static func from(json: JSON) -> Attestation? {
      guard let format = json["format"].string else { return nil }
      let data = json["data"]
      let queryIds = json["credential_ids"].arrayObject as? [String]
      return Attestation(format: format, data: data, queryIds: queryIds)
    }
  }
  
  public static func fromJson(_ jsonData: Data) -> Result<VerifierAttestations, Error> {
    do {
      let json = try JSON(data: jsonData)
      guard let array = json.array else {
        return .failure(NSError(domain: "VerifierAttestations", code: 0, userInfo: [NSLocalizedDescriptionKey: "Expected JSON array"]))
      }
      
      let attestations = array.compactMap { Attestation.from(json: $0) }
      
      guard !attestations.isEmpty else {
        return .failure(NSError(domain: "VerifierAttestations", code: 1, userInfo: [NSLocalizedDescriptionKey: "No valid attestations found"]))
      }
      
      return .success(VerifierAttestations(value: attestations))
    } catch {
      return .failure(error)
    }
  }
}
