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
@preconcurrency import SwiftyJSON

@testable import OpenID4VP

final class NetworkingMock: Networking {
  
  let json: JSON
  let statusCode: Int
  let headers: [String: String]
  
  init(
    json: JSON,
    statusCode: Int = 200,
    headers: [String: String] = [:]
  ) {
    self.json = json
    self.statusCode = statusCode
    self.headers = headers
  }
  
  func data(
    from url: URL
  ) async throws -> (Data, URLResponse) {
    let data = try json.toDictionary().toThrowingJSONData()
    let result = Result<Data, Error>.success(data)
    let response = HTTPURLResponse(
      url: .stub(),
      statusCode: statusCode,
      httpVersion: nil,
      headerFields: headers
    )
    return try (result.get(), response!)
  }
  
  func data(
    for request: URLRequest
  ) async throws -> (Data, URLResponse) {
    return try await data(from: URL(string: "https://www.example.com")!)
  }
}

