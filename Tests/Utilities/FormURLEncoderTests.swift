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
import SwiftyJSON

@testable import OpenID4VP

final class FormURLEncoderTests: XCTestCase {
  
  private func decodeFormBody(_ data: Data) -> [String: [String]] {
    guard let string = String(data: data, encoding: .ascii) else {
      XCTFail("Body is not ASCII")
      return [:]
    }
    
    var result: [String: [String]] = [:]
    
    for pair in string.split(separator: "&") {
      let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
      let namePart = String(parts[0])
      let valuePart = parts.count > 1 ? String(parts[1]) : ""
      
      let decodedName = namePart
        .replacingOccurrences(of: "+", with: " ")
        .removingPercentEncoding ?? namePart
      
      let decodedValue = valuePart
        .replacingOccurrences(of: "+", with: " ")
        .removingPercentEncoding ?? valuePart
      
      result[decodedName, default: []].append(decodedValue)
    }
    
    return result
  }
  
  func testEncodedStringSpacesBecomePlus() {
    let input = "hello world"
    let encoded = FormURLEncoder.encoded(string: input)
    XCTAssertEqual(encoded, "hello+world")
  }
  
  func testEncodedStringLeavesAllowedCharactersUnchanged() {
    let input = "Az09*-._ "
    let encoded = FormURLEncoder.encoded(string: input)
    // Space becomes '+'
    XCTAssertEqual(encoded, "Az09*-._+")
  }
  
  func testEncodedStringPercentEncodesReservedCharacters() {
    let input = "a&b=c?"
    let encoded = FormURLEncoder.encoded(string: input)
    // & = %26, = = %3D, ? = %3F
    XCTAssertEqual(encoded, "a%26b%3Dc%3F")
  }
  
  func testEncodedAnyNilBecomesEmptyString() {
    let encoded = FormURLEncoder.encoded(any: nil)
    XCTAssertEqual(encoded, "")
  }
  
  func testEncodedAnyString() {
    let encoded = FormURLEncoder.encoded(any: "hello world")
    XCTAssertEqual(encoded, "hello+world")
  }
  
  func testEncodedAnyInt() {
    let encoded = FormURLEncoder.encoded(any: 42)
    XCTAssertEqual(encoded, "42")
  }
  
  func testEncodedAnyDouble() {
    let encoded = FormURLEncoder.encoded(any: 3.14)
    XCTAssertEqual(encoded, "3.14")
  }
  
  func testEncodedAnyDictionaryNonOptionalValues() throws {
    let dict: [String: Any] = [
      "foo": "bar",
      "answer": 42
    ]
    let encoded = FormURLEncoder.encoded(any: dict)
    XCTAssertNotNil(encoded)
    
    // Decode percent-encoding back to JSON string
    let jsonString = encoded!
      .replacingOccurrences(of: "+", with: " ")
      .removingPercentEncoding!
    
    let data = Data(jsonString.utf8)
    let obj = try JSONSerialization.jsonObject(with: data, options: [])
    guard let decodedDict = obj as? [String: Any] else {
      XCTFail("Decoded JSON is not dictionary")
      return
    }
    
    XCTAssertEqual(decodedDict["foo"] as? String, "bar")
    XCTAssertEqual(decodedDict["answer"] as? Int, 42)
  }
  
  func testEncodedAnyDictionaryOptionalValues() throws {
    let dict: [String: Any?] = [
      "foo": "bar",
      "nilValue": nil,
      "num": 1
    ]
    let encoded = FormURLEncoder.encoded(any: dict)
    XCTAssertNotNil(encoded)
    
    // Decode percent-encoding back to JSON string
    let jsonString = encoded!
      .replacingOccurrences(of: "+", with: " ")
      .removingPercentEncoding!
    
    let data = Data(jsonString.utf8)
    let obj = try JSONSerialization.jsonObject(with: data, options: [])
    guard let decodedDict = obj as? [String: Any] else {
      XCTFail("Decoded JSON is not dictionary")
      return
    }
    
    XCTAssertEqual(decodedDict["foo"] as? String, "bar")
    // nil becomes NSNull()
    XCTAssertTrue(decodedDict["nilValue"] is NSNull)
    XCTAssertEqual(decodedDict["num"] as? Int, 1)
  }
  
  func testEncodedAnyUnsupportedTypeReturnsNil() {
    struct Foo {}
    let foo = Foo()
    let encoded = FormURLEncoder.encoded(any: foo)
    XCTAssertNil(encoded)
  }
  
  func testBodySingleStringPair() throws {
    let body = try FormURLEncoder.body(from: [
      "name": "John Doe"
    ])
    
    let decoded = decodeFormBody(body)
    XCTAssertEqual(decoded.count, 1)
    XCTAssertEqual(decoded["name"], ["John Doe"])
  }
  
  func testBodyMultiplePairsOrderAgnostic() throws {
    let body = try FormURLEncoder.body(from: [
      "first": "Alice",
      "last": "Smith"
    ])
    
    let decoded = decodeFormBody(body)
    XCTAssertEqual(decoded["first"], ["Alice"])
    XCTAssertEqual(decoded["last"], ["Smith"])
  }
  
  func testBodyArrayOfValues() throws {
    let body = try FormURLEncoder.body(from: [
      "tags": ["one", "two", "three"]
    ])
    
    let decoded = decodeFormBody(body)
    XCTAssertEqual(decoded["tags"]?.sorted(), ["one", "three", "two"].sorted())
  }
  
  func testBodyArrayOfOptionalValuesIncludingNil() throws {
    let values: [Any?] = ["one", nil, "three"]
    let body = try FormURLEncoder.body(from: [
      "field": values
    ])
    
    let decoded = decodeFormBody(body)
    // nil becomes empty string
    XCTAssertEqual(decoded["field"]?.sorted(), ["", "one", "three"].sorted())
  }
  
  func testBodyDictionaryValueEncodedAsJson() throws {
    let payload: [String: Any] = [
      "foo": "bar",
      "num": 99
    ]
    
    let body = try FormURLEncoder.body(from: [
      "payload": payload
    ])
    
    let decoded = decodeFormBody(body)
    guard let payloadValues = decoded["payload"], payloadValues.count == 1 else {
      XCTFail("Expected a single payload value")
      return
    }
    
    let jsonString = payloadValues[0]
    let data = Data(jsonString.utf8)
    let obj = try JSONSerialization.jsonObject(with: data, options: [])
    guard let decodedPayload = obj as? [String: Any] else {
      XCTFail("Decoded payload is not dictionary")
      return
    }
    
    XCTAssertEqual(decodedPayload["foo"] as? String, "bar")
    XCTAssertEqual(decodedPayload["num"] as? Int, 99)
  }
  
  func testBodyDictionaryOptionalValueEncodedAsJson() throws {
    let payload: [String: Any?] = [
      "foo": "bar",
      "maybe": nil
    ]
    
    let body = try FormURLEncoder.body(from: [
      "payload": payload
    ])
    
    let decoded = decodeFormBody(body)
    guard let payloadValues = decoded["payload"], payloadValues.count == 1 else {
      XCTFail("Expected a single payload value")
      return
    }
    
    let jsonString = payloadValues[0]
    let data = Data(jsonString.utf8)
    let obj = try JSONSerialization.jsonObject(with: data, options: [])
    guard let decodedPayload = obj as? [String: Any] else {
      XCTFail("Decoded payload is not dictionary")
      return
    }
    
    XCTAssertEqual(decodedPayload["foo"] as? String, "bar")
    XCTAssertTrue(decodedPayload["maybe"] is NSNull)
  }
  
  func testBodyUnsupportedValueTypeThrows() {
    let form: [String: Any] = [
      "bad": Date() // not supported
    ]
    
    XCTAssertThrowsError(try FormURLEncoder.body(from: form))
  }
  
  func testBodyIsAsciiEncoded() throws {
    let body = try FormURLEncoder.body(from: [
      "key": "value"
    ])
    
    // Already created with .ascii, but ensure it round-trips
    let string = String(data: body, encoding: .ascii)
    XCTAssertEqual(string, "key=value")
  }
}

