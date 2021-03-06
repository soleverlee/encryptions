import Foundation
import CommonCrypto

struct AES {
    private let key: Data
    private let iv: Data
    private let mode: String
    private let padding: String
    
    init(key: Data, iv: Data, mode: String, padding: String) throws{
        guard key.count == kCCKeySizeAES256 || key.count == kCCKeySizeAES128 else {
            throw Error.badKeyLength
        }
        if(mode == "CBC"){
            guard (iv.count == kCCBlockSizeAES128) else {
                throw Error.badInputVectorLength
            }
        }
        
        self.key = key
        self.iv  = iv
        self.mode = mode
        self.padding = padding
    }
    
    enum Error: Swift.Error {
        case keyGeneration(status: Int)
        case cryptoFailed(status: CCCryptorStatus)
        case badKeyLength
        case badInputVectorLength
        case unknownPadding
    }
    
    func encrypt(raw: Data) throws-> Data {
        return try crypt(data: raw, option: CCOperation(kCCEncrypt))
    }
    
    func decrypt(raw: Data) throws-> Data {
        return try crypt(data: raw, option: CCOperation(kCCDecrypt))
    }
    
    func getCCOptions() throws -> Int {
        var options:Int;
        switch(padding) {
        case "NoPadding":
            options = ccNoPadding;
            break;
        case "PKCS5Padding":
            options = kCCOptionPKCS7Padding;
            break;
        default:
            throw Error.unknownPadding;
        }
        if(mode == "ECB"){
            options += kCCOptionECBMode;
        }
        return options;
    }
    
    func crypt(data: Data, option: CCOperation) throws -> Data {
        var outputBytes  = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128);
        
        var outputLength = Int(0)
        let paddingOption = try getCCOptions();
        
        let status = data.withUnsafeBytes { dataBytes in
            iv.withUnsafeBytes { ivBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        option,                       // encrypt | decrypt
                        CCAlgorithm(kCCAlgorithmAES), // aes
                        CCOptions(paddingOption),     // padding
                        keyBytes,                     // key
                        key.count,                    // 128 | 256
                        ivBytes,                      // iv
                        dataBytes,                    // raw input
                        data.count,                   // raw input length
                        &outputBytes,                 // output
                        outputBytes.count,            // output length
                        &outputLength)                // actual output size
                }
            }
        }
        
        guard status == kCCSuccess else {
            print(status)
            throw Error.cryptoFailed(status: status)
        }
        
        return Data(bytes: UnsafePointer<UInt8>(outputBytes), count: outputLength)
    }
}

extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }
    
    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}
