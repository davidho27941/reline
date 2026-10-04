import Foundation

public enum BookmarkError: Error, Equatable {
    case missing(String)
    case stale(String)
    case unresolvable(String)
}

/// Security-scoped bookmark lifecycle for user-selected folders.
///
/// Access is started only for the duration of `withAccess` and stopped afterwards, so the app
/// never holds scope on a folder while idle. A stale bookmark is reported, never silently
/// re-created: the caller re-selects the folder through the picker.
public final class BookmarkStore: @unchecked Sendable {
    private let defaults: UserDefaults
    private let prefix: String

    public init(defaults: UserDefaults = .standard, prefix: String = "bookmark.") {
        self.defaults = defaults
        self.prefix = prefix
    }

    private func key(_ name: String) -> String { prefix + name }

    public func save(_ url: URL, as name: String) throws {
        let data = try url.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
        defaults.set(data, forKey: key(name))
    }

    public func remove(_ name: String) { defaults.removeObject(forKey: key(name)) }

    public func hasBookmark(_ name: String) -> Bool { defaults.data(forKey: key(name)) != nil }

    /// Resolve a bookmark. Throws `.stale` when macOS reports the bookmark as stale; the caller
    /// must then ask the user to reselect (and `save` again).
    public func resolve(_ name: String) throws -> URL {
        guard let data = defaults.data(forKey: key(name)) else { throw BookmarkError.missing(name) }
        var stale = false
        let url: URL
        do {
            url = try URL(resolvingBookmarkData: data, options: [.withSecurityScope, .withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale)
        } catch {
            throw BookmarkError.unresolvable(name)
        }
        if stale { throw BookmarkError.stale(name) }
        return url
    }

    /// Run `body` with security-scoped access to `url`, releasing the scope afterwards even on error.
    public func withAccess<T>(_ url: URL, _ body: (URL) throws -> T) throws -> T {
        let granted = url.startAccessingSecurityScopedResource()
        defer { if granted { url.stopAccessingSecurityScopedResource() } }
        return try body(url)
    }
}
