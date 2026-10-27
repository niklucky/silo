import Foundation
import SafariServices
import os.log

/// Safari's `silo-native-host`. Safari cannot start a native messaging host,
/// so `browser.runtime.sendNativeMessage` lands here instead, one request per
/// message. Each one is forwarded to the agent socket as a JSON line and the
/// agent's reply goes back unchanged.
///
/// Transport failures come back as `{"bridge_error": "..."}`, which the
/// extension reports the way it reports a missing native host elsewhere.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private static let log = Logger(subsystem: "dev.silo.safari.extension", category: "bridge")

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let reply: Any
        do {
            reply = try Self.forward(item?.userInfo?[SFExtensionMessageKey])
        } catch let failure as BridgeFailure {
            Self.log.error("\(failure.message, privacy: .public)")
            reply = ["bridge_error": failure.message]
        } catch {
            reply = ["bridge_error": error.localizedDescription]
        }
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: reply]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }

    /// Browsers cannot read old revisions or change where the vault syncs.
    /// Keep in step with silo-native-host.
    private static let refused: Set<String> = [
        "shutdown", "history",
        "sync_register", "sync_login", "sync_logout", "sync_revoke_device",
        "connections", "connect", "disconnect", "verify_peer", "share", "add_local",
    ]

    private static func forward(_ message: Any?) throws -> Any {
        guard let request = message as? [String: Any], let method = request["method"] as? String else {
            return refusal("malformed request")
        }
        if refused.contains(method) { return refusal("this method is not available through the browser") }
        var line = try JSONSerialization.data(withJSONObject: request)
        line.append(0x0A)
        defer { line.resetBytes(in: 0..<line.count) }
        var answer = try AgentSocket.call(line)
        defer { answer.resetBytes(in: 0..<answer.count) }
        return try JSONSerialization.jsonObject(with: answer)
    }

    private static func refusal(_ message: String) -> [String: Any] {
        ["err": ["code": "invalid", "message": message]]
    }
}

struct BridgeFailure: Error {
    let message: String
}

/// One connection per request to `~/.silo/agent.sock`, the only socket the
/// sandbox lets this extension reach (see Extension.entitlements).
enum AgentSocket {
    /// The real home directory: inside the sandbox `HOME` is the container.
    static var path: String {
        let home = getpwuid(getuid()).flatMap { String(validatingCString: $0.pointee.pw_dir) } ?? NSHomeDirectory()
        return home + "/.silo/agent.sock"
    }

    static func call(_ line: Data) throws -> Data {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BridgeFailure(message: "socket: \(errnoText())") }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = Self.path
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard path.utf8.count < capacity else { throw BridgeFailure(message: "socket path too long: \(path)") }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            if errno == ENOENT || errno == ECONNREFUSED {
                throw BridgeFailure(message: "the Silo agent is not running (\(path))")
            }
            throw BridgeFailure(message: "cannot reach the agent at \(path): \(errnoText())")
        }

        try line.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = write(fd, raw.baseAddress! + sent, raw.count - sent)
                guard n > 0 else { throw BridgeFailure(message: "write: \(errnoText())") }
                sent += n
            }
        }

        var reply = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        defer { chunk.withUnsafeMutableBytes { _ = memset($0.baseAddress!, 0, $0.count) } }
        while reply.last != 0x0A {
            let n = read(fd, &chunk, chunk.count)
            guard n > 0 else { throw BridgeFailure(message: n == 0 ? "agent closed the connection" : "read: \(errnoText())") }
            reply.append(contentsOf: chunk[0..<n])
        }
        return reply
    }

    private static func errnoText() -> String {
        String(cString: strerror(errno))
    }
}
