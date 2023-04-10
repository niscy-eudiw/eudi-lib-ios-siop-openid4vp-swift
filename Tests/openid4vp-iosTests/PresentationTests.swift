import XCTest
import JSONSchema

@testable import openid4vp_ios

final class PresentationTests: XCTestCase {
  func testPresentationDefinitionDecoding() throws {
    
    let parser = Parser()
    let result: Result<PresentationDefinitionContainer, ParserError> = parser.decode(
      path: "input_descriptors_example",
      type: "json"
    )
    
    let container = try? result.get()
    guard
      let container = container
    else {
      XCTAssert(false)
      return
    }
    
    XCTAssert(container.definition.id == "32f54163-7166-48f1-93d8-ff217bdb0653")
    XCTAssert(true)
  }
  
  func testPresentationDefinitionJsonStringDecoding() throws {
    
    let definition = try! Dictionary.from(
      localJSONfile: "minimal_example"
    ).get().toJSONString()!
    
    let result: Result<PresentationDefinitionContainer, ParserError> = Parser().decode(json: definition)
    
    let container = try! result.get()
    
    XCTAssert(container.definition.id == "32f54163-7166-48f1-93d8-ff217bdb0653")
  }
  
  func testValidatePresentationDefinitionAgainstSchema() throws {
    
    let schema = try! Dictionary.from(
      localJSONfile: "presentation-definition-envelope"
    ).get()
    
    let parser = Parser()
    let result: Result<PresentationDefinitionContainer, ParserError> = parser.decode(
      path: "input_descriptors_example",
      type: "json"
    )
    
    let container = try! result.get()
    let definition = try! DictionaryEncoder().encode(container.definition)
    
    let errors = try! validate(
      definition,
      schema: schema
    ).errors
    
    XCTAssertNil(errors)
  }
  
  func testValidateMdlExamplePresentationDefinitionAgainstSchema() throws {
    
    let schema = try! Dictionary.from(
      localJSONfile: "presentation-definition-envelope"
    ).get()
    
    let parser = Parser()
    let result: Result<PresentationDefinition, ParserError> = parser.decode(
      path: "mdl_example",
      type: "json"
    )
    
    let container = try! result.get()
    let definition = try! DictionaryEncoder().encode(container)
    
    let errors = try! validate(
      definition,
      schema: schema
    ).errors
    
    XCTAssertNil(errors)
  }
  
  func testValidateMdlExamplePresentationDefinitionExpectedData() throws {
    
    let parser = Parser()
    let result: Result<PresentationDefinition, ParserError> = parser.decode(
      path: "mdl_example",
      type: "json"
    )
    
    let presentationDefinition = try! result.get()
    XCTAssertTrue(presentationDefinition.inputDescriptors.first!.format!.msoMdoc!.alg.count == 2)
    XCTAssertTrue(presentationDefinition.inputDescriptors.first!.format!.msoMdoc!.alg.last == "ES256")
  }
}