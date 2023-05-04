import Foundation

public typealias ClaimId = String
public typealias Purpose = String
public typealias Name = String
public typealias InputDescriptorId = String
public typealias Group = String
public typealias JSONPath = String
public typealias Match = [ClaimId: [
  [InputDescriptorId: [(JSONPath, Any)]]
]]